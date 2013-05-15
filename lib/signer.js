var bignum = require('bignum');

var config = require('../config');

var Signer = function () {
  if ("object" !== typeof config.rsa)
    throw new Error('Config error: config.rsa is not an object');

  if ("string" !== typeof config.rsa.d)
    throw new Error('Config.error: config.rsa.d is not a string');

  if ("string" !== typeof config.rsa.e)
    throw new Error('Config error: config.rsa.e is not a string');

  this.d = bignum(config.rsa.d, 16);
  this.n = bignum(config.rsa.n, 16);
};

Signer.prototype.sign = function (signreq) {
  // XXX We need to derive a different secret for each account

  var mr = bignum(signreq, 16);
  var mrd = mr.powm(this.d, this.n);
  return mrd.toString(16);
};
exports.Signer = Signer;

