import fs from 'fs';
const args = process.argv.slice(2);
function showMsg() {
  console.error("Input inserted: ", args, "\n");
  console.error("Error, Filename not found");
  console.log("\nUSAGE:");
  console.log("\tnode dtr_tenable_comparison.js -t TENABLE-FILENAME.FileExtension -d DTR-FILENAME.FileExtension\n");
  process.exit(9); // 9 = Invalid Argument
}
const getDTRFileFromIndex = (args.indexOf('-d') + 1) || (args.indexOf('-D') + 1) || (args.indexOf('--DTR') + 1) || (args.indexOf('--dtr') + 1);
const getTenableFileFromIndex = (args.indexOf('-t') + 1) || (args.indexOf('-T') + 1) || (args.indexOf('--Tenable') + 1) || (args.indexOf('--TENABLE') + 1);
const dtrFileName = getDTRFileFromIndex > 0 ? args[getDTRFileFromIndex] : showMsg();
const tenableFileName = getTenableFileFromIndex > 0 ? args[getTenableFileFromIndex] : showMsg();

try {
    var dtr = JSON.parse(fs.readFileSync(dtrFileName, {encoding: 'utf-8'} ));
    var tenable = JSON.parse(fs.readFileSync(tenableFileName, {encoding: 'utf-8'} )); 
} catch (error) {
    console.error('There was an error while trying to open and read the file:', error);
    process.exit(0);
}

const tenableCVE = tenable.findings.map(el => el.nvdFinding.cve);
const dtrCVEs = [...new Set([...dtr.deep.flatMap(el => el.vulnerabilities.map(v => v.CVE)), ...dtr.shallow.map(el => el.CVE)])].filter(e => e).flatMap(e => e);
const folderToWrite = "./export/";
const duplicates = dtrCVEs.filter(val => tenableCVE.indexOf(val) !== -1);


fs.writeFileSync(folderToWrite + 'DUPLICATES_' + Date.now() +'.json', JSON.stringify(duplicates, null, 2), {
    encoding: 'utf-8'
  });