const argv          = require('yargs').argv
const fs            = require('fs');
const path          = require('path');

// Check for all arguments
if (!argv.id||!argv.title||!argv.attribute||!argv.value||!argv.domain) {
    console.log("Usage: node pushorgid --id <id> --title <title> --attribute <attribute> --value <value> --domain <value>")
    console.log();
    process.exit();
}

// Locate the domain to read config
var site = "";
const config = JSON.parse(fs.readFileSync(path.join(__dirname, '../data', 'config.json')));

for(var entry in config) {
    if (config[entry].domain===argv.domain) { site = entry }
}

if (!site) {
    console.log("Specified domain was not found in config")
    console.log();
    process.exit();
}

// Load the provider as configured
const eidprovider   = require('npm eid-provider')('frejaorgid')
const eidconfig = eidprovider.settings[config[site].profile];
for(var override in config[site].settings) {
  if (override==='ca_cert'||override==='jwt_cert'||override==='client_cert'){
    eidconfig[override] = fs.readFileSync(path.join(__dirname, config[site].settings[override]));
  } else {
    eidconfig[override] = config[site].settings[override];
  }
}
eidprovider.initialize(eidconfig);

var whom = {
  type: "SSN",
  ssn: argv.id
}

// Do the stuff
eidprovider.addOrgIdRequest(whom,argv.title,argv.attribute,argv.value, (status)=>{
    console.log(status);
}, (status)=>{
    console.log(status);
}).then((status)=>{
    console.log(status);
    console.log();
});