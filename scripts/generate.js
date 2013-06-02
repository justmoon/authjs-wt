var fs = require('fs');

var KeyGenenerator = require('../lib/keygen').KeyGenerator;

var bits = 2048;

console.log("Generating "+bits+"-bit RSA keypair, please wait...");

var keygen = new KeyGenenerator(bits);
keygen.verbose = true;
var rsa = keygen.generate();

fs.writeFileSync('rsa.json', JSON.stringify(rsa));

console.log("***PRIVATE***");
console.log("d   = "+rsa.d.match(/.{1,64}/g).join('\n      '));
console.log("phi = "+rsa.phi.match(/.{1,64}/g).join('\n      '));
console.log("***PUBLIC***");
console.log("e   = 0x"+rsa.e);
console.log("a   = "+rsa.a.match(/.{1,64}/g).join('\n      '));
console.log("n   = "+rsa.n.match(/.{1,64}/g).join('\n      '));
console.log("Wrote rsa.json");
