import converter from 'json-2-csv';
import fetch from 'node-fetch';
import fs from "fs";
import nReadlines from 'n-readlines';
import 'dotenv/config'

// ALL LATEST CVEs downlaod link https://cve.mitre.org/data/downloads/allitems.csv
// NIST API - Get CVE data - https://services.nvd.nist.gov/rest/json/cve/1.0/{{CVE}}?apiKey={{APIkey}}

const args = process.argv.slice(2);
function showMsg() {
  console.error("Input inserted: ", args, "\n");
  console.error("Error, Filename not found");
  console.log("\nUSAGE:");
  console.log("\tnode docker_scan_transformer.js -f FILENAME.FileExtension\n");
  console.log("\tN.B. The file should be in the same directory of the JS script.\n");
  process.exit(9); // 9 = Invalid Argument
}
const getFileFromIndex = (args.indexOf('-f') + 1) || (args.indexOf('-F') + 1) || (args.indexOf('--filename') + 1);
const fileName = getFileFromIndex > 0 ? args[getFileFromIndex] : showMsg();
const CVEurl = 'https://services.nvd.nist.gov/rest/json/cve/1.0/';
const apiKey = process.env.NIST_API_KEY || '';

try { var broadbandLines = new nReadlines(fileName); } catch (error) { console.error("There was an error during the file opening: ", error); process.exit(9) }

const toSnakeCase = string => string.toLowerCase().replace(/ /g, '_');
// vulnerabilities on top
const shallowVulns = [];
// vulnerabilities in-deep after the "on-top" ones
const deepVulns = [];
let currLine;
let shallowVuln = {};
let vulnPackage;
let fixable = [];
let unfixables = [];
let deepVuln;
let childDeepVuln;

while (currLine = broadbandLines.next()) {
  const line = currLine.toString('utf-8').trim();
  let match;
  if ((match = line.match(/^\S+ (Medium|Low|High|Critical) severity vulnerability found in (.+)/))) {
    shallowVuln = { package: match[2], CVE: undefined, severity: match[1], CVSS3: undefined, CVSS2: undefined, snykCVSS: undefined };
    shallowVulns.push(shallowVuln);
  } else if ((match = line.match(/^(Description|Info|Introduced through|From): (.+)/))) {
    shallowVuln[toSnakeCase((match[1] === "Info" ? "reference" : match[1]))] = match[2];
  } else if (line === 'Issues to fix by upgrading:') {
    deepVuln = undefined;
  } else if (line === 'Issues with no direct upgrade or patch:') {
    deepVuln = undefined;
    vulnPackage = undefined;
  } else if ((match = line.match(/^Upgrade (\S+) to (\S+) to fix/))) {
    vulnPackage = {
      from: match[1],
      to: match[2],
      vulnerabilities: []
    };
    fixable.push(vulnPackage);
  } else if ((match = line.match(/^\S+ ([^\[]+?) \[(Low|Medium|High|Critical) Severity\]\[(.+?)\] in (.*)/))) {
    childDeepVuln = {
      name: match[1],
      severity: match[2],
      reference: match[3],
      package: match[4],
      fixed: vulnPackage?.to.split('@')[1]
    };
    (vulnPackage ? vulnPackage.vulnerabilities : unfixables).push(childDeepVuln);
  } else if ((match = line.match(/This issue was fixed in versions: (.+)/))) {
    childDeepVuln.fixed = match[1];
  } else if ((match = line.match(/^(Organization|Package manager|Target file|Project name|Docker image|Licenses): {3,}(.+)/))) {
    if (!deepVuln) {
      deepVuln = {
        vulnerabilities: [
          ...fixable.flatMap(({ from, to, vulnerabilities }) => {
            const [vulnerable_name, vulnerable_version] = from.split('@');
            const [fixed_name, fixed_version] = to.split('@');
            return vulnerabilities.map(vuln => ({
              name: vuln.name,
              CVE: undefined,
              severity: vuln.severity,
              CVSS3: undefined,
              CVSS2: undefined,
              snykCVSS: undefined,
              mitigation: `Upgrade ${from} to ${to}`,
              reference: vuln.reference,
              fixable: true,
              package: {
                name: vulnerable_name,
                vulnerable_name,
                fixed_name,
                vulnerable_version,
                fixed_version,
                full_vulnerable: from,
                full_fixed: to
              }
            }));
          }),
          ...unfixables.map(vuln => {
            const [packageName, version] = vuln.package.split('@');
            return {
              name: vuln.name,
              CVE: undefined,
              severity: vuln.severity,
              CVSS3: undefined,
              CVSS2: undefined,
              snykCVSS: undefined,
              mitigation: 'N/A',
              reference: vuln.reference,
              fixable: false,
              package: {
                name: packageName,
                vulnerable_name: packageName,
                fixed_name: vuln.fixed ? packageName : 'N/A',
                vulnerable_version: version,
                fixed_version: vuln.fixed || 'N/A',
                full_vulnerable: vuln.package,
                full_fixed: vuln.fixed ? `${packageName}@${vuln.fixed}` : 'N/A'
              }
            };
          })
        ]
      };
      if (fixable.length > 0 || unfixables.length > 0) {
        deepVulns.push(deepVuln);
      }
      fixable = [];
      unfixables = [];
    }
    deepVuln[toSnakeCase(match[1])] = match[2];
  }
}

// Add CVE to all vulns
const dtrAllReferences = [...new Set([...deepVulns.flatMap(el => el.vulnerabilities.map(vuln => vuln.reference)), ...shallowVulns.map(el => el.reference)])].filter(e => e).flatMap(e => e);
let dtrCVEs = [];
let remainings = [];

async function getBody(url, json=false) {
  const response = await fetch(url,{
    redirect: 'follow',
    follow: 10,
  })
  let text;
  if (json) {
    text = await response.json()
  } else {
    text = await response.text()
  }
  return text
}

let counter = 1;
let size = dtrAllReferences.length;

for(const url of dtrAllReferences) {
  console.log(`(${counter} / ${size}) Analyzing this reference url: ${url}`);
  counter++;
  const body = await getBody(url).catch(err => console.error("(1) ERROR with this url -> " + url + ": ", err));
  // const cveRegex = [...new Set(body.match(/CVE-\d{4}-\d{4,7}/g))]; // THEN USE cveRegex[0] as variable
  const cveRegex = (body.match(/target=\"_blank\" id="(CVE-\d{4}-\d{4,7})"/) || ['', "N/A"])[1];
  const snykCVSS = (body.match(/data-snyk-test-score="(\d*\.?\d+)"/) || ['', "N/A"])[1];
  const nistComposedUrl = CVEurl+cveRegex+'?apiKey='+apiKey;
  if (cveRegex !== 'N/A' && cveRegex !== '') {
    console.log(`\tGot CVE id: ${cveRegex}.\n\tNow analyzing this url: ${nistComposedUrl}\n`)
    const cveBody = await getBody(nistComposedUrl,true).catch(err => {
      console.error("(2) ERROR with this url -> " + nistComposedUrl + ": ", err)
      if (cveRegex) {
        console.log(`\t>\tAdding ${cveRegex} to the remainings list, 'cause it's causing troubles.\n`)
        remainings.push({url: nistComposedUrl, CVE: cveRegex,  reference: url, snykCVSS: snykCVSS})
      }
    });  
    dtrCVEs.push({
      CVE: cveRegex || 'N/A', 
      reference: url, 
      CVSS3: cveBody?.result?.CVE_Items[0]?.impact?.baseMetricV3?.cvssV3?.baseScore || 'N/A',
      CVSS2: cveBody?.result?.CVE_Items[0]?.impact?.baseMetricV2?.cvssV2?.baseScore || 'N/A', 
      snykCVSS: snykCVSS
    })
    await new Promise(resolve => setTimeout(resolve, 1050));
  } else {
    dtrCVEs.push({
      CVE: 'N/A', 
      reference: url, 
      CVSS3: 'N/A',
      CVSS2: 'N/A', 
      snykCVSS: snykCVSS || 'N/A'
    })
  }
  
  
}


await new Promise(resolve => setTimeout(resolve, 1000));
console.log(`#####################################################################\nNow analyze remainings urls\n#####################################################################\n\n`);
counter = 1;
size = remainings.length;
await new Promise(resolve => setTimeout(resolve, 1000));


for (const el of remainings) {
  console.log(`(${counter} / ${size}) Analyzing the CVE ${el?.CVE || '[something wrong]'} reference url: ${el?.reference || '[something wrong]'};`);
  console.log(`HTTP.GET\t( ${el?.url || '[something wrong]'} )\n`)
  counter++;
  const url = el.url;
  const cveBody = await getBody(nistComposedUrl,true).catch(err => console.error("(3) ERROR with this url -> " + url + ": ", err));
  dtrCVEs.push({
    CVE: el?.CVE || 'N/A', 
    reference: el?.reference, 
    CVSS3: cveBody?.result?.CVE_Items[0]?.impact?.baseMetricV3?.cvssV3?.baseScore || 'N/A',
    CVSS2: cveBody?.result?.CVE_Items[0]?.impact?.baseMetricV2?.cvssV2?.baseScore || 'N/A', 
    snykCVSS: el?.snykCVSS || 'N/A'
  })
  await new Promise(resolve => setTimeout(resolve, 1000));
}


dtrCVEs.map(el => {
  deepVulns.map(deep => deep.vulnerabilities.map(d => {
    if (d.reference === el.reference) {
      d['CVE'] = el.CVE;
      d['CVSS3'] = el.CVSS3
      d['CVSS2'] = el.CVSS2
      d['snykCVSS'] = el.snykCVSS
    }
  }))
  shallowVulns.map(s => {
    if (s.reference === el.reference) {
      s['CVE'] = el.CVE
      s['CVSS3'] = el.CVSS3
      s['CVSS2'] = el.CVSS2
      s['snykCVSS'] = el.snykCVSS
    }
  })
})

// Order arrays by vuln severity
const keyOrder ={
  "Critical": 1,
  "High": 2,
  "Medium": 3,
  "Low": 4,
  default: Infinity
};
deepVulns.map(el => el.vulnerabilities.sort((a,b) => (keyOrder[a.severity] || order.default) - (keyOrder[b.severity] || order.default)));
shallowVulns.sort((a,b) => (keyOrder[a.severity] || order.default) - (keyOrder[b.severity] || order.default));

// Write JSON to files *.json
const folderToWrite = "./export/";
const fileToWrite = fileName.split('/');
const finalDestination = fileToWrite[fileToWrite.length - 1]

const finalJSON = {
  deep: deepVulns,
  shallow: shallowVulns
}

// WRITE FULL JSON FILE
fs.writeFileSync(folderToWrite + finalDestination + '.json', JSON.stringify(finalJSON, null, 2), {
  encoding: 'utf-8'
});


// transform in CSV

converter.json2csv(shallowVulns, (err, csv) => {
  if (err) {
    throw err;
  }
  // write CSV to a file
  fs.writeFileSync(folderToWrite + "shallow_" + finalDestination + '.csv', csv);
});

// DEEP CSV Creation

let deepCSVArray = []
deepVulns.forEach(element => {
  element.vulnerabilities.forEach(el => {
    deepCSVArray.push({
      target_file: element.target_file,
      CVE: el.CVE || 'N/A',
      CVSS3: el.CVSS3 || 'N/A',
      CVSS2: el.CVSS2 || 'N/A',
      fixable: el.fixable,
      vulnerability_name: el.name,
      vulnerability_severity: el.severity,
      package_name: el.package.name,
      package_vuln_version: el.package.vulnerable_version,
      package_fix_version: el.package.fixed_version,
      mitigation: el.mitigation,
      reference: el.reference
    })
  })
});

converter.json2csv(deepCSVArray, (err, csv) => {
  if (err) {
    throw err;
  }
  // write CSV to a file
  fs.writeFileSync(folderToWrite + "deep_" + finalDestination + '.csv', csv);
});



const used = process.memoryUsage().heapUsed / 1024 / 1024;
console.log(`The script uses approximately ${Math.round(used * 100) / 100} MB`);