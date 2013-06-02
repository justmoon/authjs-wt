var bignum = require('bignum');
var crypto = require('crypto');

var config = require('../config');

var Signer = function () {
  if ("object" !== typeof config.rsa)
    throw new Error('Config error: config.rsa is not an object');

  if ("string" !== typeof config.rsa.d)
    throw new Error('Config.error: config.rsa.d is not a string');

  if ("string" !== typeof config.rsa.e)
    throw new Error('Config error: config.rsa.e is not a string');

  this.e = bignum(config.rsa.e, 16);
  this.d = bignum(config.rsa.d, 16);
  this.phi = bignum(config.rsa.phi, 16);
  this.n = bignum(config.rsa.n, 16);
};

// Full domain hash based on SHA512
function fdh(data, bytelen)
{
  if (typeof data === "string") {
    data = new Buffer(data, "utf8");
  }

  // Add hashing rounds until we exceed desired length in bits
  var counter = 0, output = new Buffer(0);
  while (output.length < bytelen) {
    var buf = Buffer.concat([new Buffer([
      counter >>> 24,
      counter >>> 16,
      counter >>>  8,
      counter >>>  0
    ]), data]);
    var hash = crypto.createHash('sha512').update(buf).digest();
    output = Buffer.concat([output, hash]);
    counter++;
  }

  // Truncate to desired length
  output = output.slice(0, bytelen);

  return output;
}

Signer.prototype.sign = function (info, signreq) {
  // XXX Check public info for validity
  //     - Must start with "PAKDF_1_0_0"
  //     - Followed by servername length (ASCII number, no leading zeros)
  //     - Followed by this server's servername (must not contain colon)
  //     - Followed by username length (ASCII number, no leading zeros)
  //     - Followed by a valid username (must not contain colon)
  //     - Separated by colons
  //     - Terminated by a colon
  //     - And no extra characters
  var publen = Math.ceil(Math.min((7+this.n.bitLength()) >>> 3, 256)/8);
  var vbuf = fdh(info, publen);
  // Last bit must be set
  vbuf[vbuf.length-1] |= 1;
  var v = bignum.fromBuffer(vbuf);
  var m = bignum(signreq, 16);
  // XXX Verify Jacobi ( m | n ) = 1
  if (m.jacobi(this.n) !== 1)
    throw new Error("Invalid signing request (Jacobi symbol != -1)");
  var s = m.powm(this.d.mul(v.invertm(this.phi)), this.n);
  return s.toString(16);
};
exports.Signer = Signer;

