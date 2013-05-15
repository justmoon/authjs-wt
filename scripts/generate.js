var fs = require('fs');

var KeyGenenerator = require('../lib/keygen').KeyGenerator;

var keygen = new KeyGenenerator();

var rsa = keygen.generate();

fs.writeFileSync('rsa.json', JSON.stringify(rsa));
console.log("Wrote rsa.json");
