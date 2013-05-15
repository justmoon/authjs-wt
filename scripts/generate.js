var fs = require('fs');

var KeyGenenerator = require('../lib/keygen').KeyGenerator;

var keygen = new KeyGenenerator();

console.log("Generating RSA keypair...");
var rsa = keygen.generate();

fs.writeFileSync('rsa.json', JSON.stringify(rsa));

console.log("e = 0x"+rsa.e);
console.log("d = "+rsa.d.match(/.{1,64}/g).join('\n    '));
console.log("n = "+rsa.n.match(/.{1,64}/g).join('\n    '));
console.log("Wrote rsa.json");
