var crypto = require('crypto'),
    BigInteger = require('../third_party/jsbn/jsbn').BigInteger;

var KeyGenerator = function (L, e) {
  this.L = L || 512;
  this.e = e || 65537;
};

// Based on GNU classpath java.security.key.rsa.RSAKeyPairGenerator
KeyGenerator.prototype.generate = function ()
{
  var e = new BigInteger(""+this.e, 10);

  var L = this.L;
  var M = (L + 1) >> 1;

  var ONE = BigInteger.ONE;
  var TWO = ONE.add(ONE);

  var lower = TWO.pow(M - 1);
  var upper = TWO.pow(M).subtract(ONE);

  var p, q, n;

  var rlen = (M + 7) >> 3, rbytes;
  step1: while (true) {
    // Generate a random number with an extra zero byte up front, otherwise
    // BigInteger might interpret it as a negative number.
    rbytes = crypto.randomBytes(rlen+1);
    rbytes[0] = 0;
    p = new BigInteger(rbytes, 256).setBit(0);
    if (p.compareTo(lower) >= 0 && p.compareTo(upper) <= 0
        && p.isProbablePrime(80) && p.gcd(e).equals(ONE))
      break step1;
  }

  step2: while (true) {
    rbytes = crypto.randomBytes(rlen+1);
    rbytes[0] = 0;
    q = new BigInteger(rbytes, 256).setBit(0);
    n = p.multiply(q);
    if (n.bitLength() == L && q.isProbablePrime(80) && q.gcd(e).equals(ONE))
      break step2;
    // TODO: test for p != q
  }

  var phi = p.subtract(ONE).multiply(q.subtract(ONE));
  var d = e.modInverse(phi);

  var rsa = {
    d: d.toString(16),
    e: e.toString(16),
    n: n.toString(16)
  };

  return rsa;
}


exports.KeyGenerator = KeyGenerator;
