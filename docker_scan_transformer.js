const fs = require('fs');
const nReadlines = require('n-readlines');
const converter = require('json-2-csv');
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
    shallowVuln = { package: match[2], severity: match[1] };
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
              severity: vuln.severity,
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
              severity: vuln.severity,
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

const used = process.memoryUsage().heapUsed / 1024 / 1024;
console.log(`The script uses approximately ${Math.round(used * 100) / 100} MB`);


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

// DEEP JSON FILE
fs.writeFileSync(folderToWrite + 'deep_' + finalDestination + '.json', JSON.stringify(deepVulns, null, 2), {
  encoding: 'utf-8'
});
// SHALLOW JSON FILE
fs.writeFileSync(folderToWrite + 'shallow_' + finalDestination + '.json', JSON.stringify(shallowVulns, null, 2), {
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