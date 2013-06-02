var crypto = require('crypto'),
    BigInteger = require('../third_party/jsbn/jsbn').BigInteger,
    bignum = require('bignum');

var KeyGenerator = function (L, e) {
  this.L = L || 512;
  this.e = e || 65537;
};

// Based on GNU classpath java.security.key.rsa.RSAKeyPairGenerator
KeyGenerator.prototype.generate = function ()
{
  var e = bignum(this.e);

  var L = this.L;
  var M = (L + 1) >> 1;

  var ONE = bignum(1);
  var TWO = bignum(2);

  var lower = TWO.pow(M - 1);
  var upper = TWO.pow(M).sub(ONE);

  var p, q, n, a;

  this.verbose && console.log("Generating p...");
  for (;;) {
    p = bignum.prime(M, true);
    if (p.cmp(lower) >= 0 && p.cmp(upper) <= 0 && p.gcd(e).eq(ONE))
      break;
  }

  this.verbose && console.log("Generating q...");
  for (;;) {
    q = bignum.prime(M, true);
    n = p.mul(q);
    if (n.bitLength() == L && q.gcd(e).eq(ONE))
      break;
    // TODO: test for p != q
  }

  this.verbose && console.log("Generating a...");
  for (;;) {
    a = n.rand();
    if (a.jacobi(n) === -1)
      break;
  }

  var phi = p.sub(ONE).mul(q.sub(ONE));
  var d = e.invertm(phi);

  var rsa = {
    d: d.toString(16),
    phi: phi.toString(16),
    a: a.toString(16),
    e: e.toString(16),
    n: n.toString(16)
  };

  return rsa;
}


exports.KeyGenerator = KeyGenerator;
