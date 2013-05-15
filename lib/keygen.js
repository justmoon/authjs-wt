var KeyGenerator = function (L, e) {
  this.L = L || 512;
  this.e = e || 65537;
};

KeyGenerator.prototype.generate = function ()
{
  var rng = new SecureRandom();

  var e = nbv(this.e);

  var L = this.L;
  var M = (L + 1) / 2;

  var ONE = nbv(1);
  var TWO = nbv(2);

  var lower = TWO.pow(M - 1);
  var upper = TWO.pow(M).subtract(ONE);

  var p, q, n;

  step1: while (true) {
    p = new BigInteger(M, rng);
    if (p.compareTo(lower) >= 0 && p.compareTo(upper) <= 0
        && p.isProbablePrime(80) && p.gcd(e).equals(ONE))
      break step1;
  }

  step2: while (true) {
    q = new BigInteger(M, rng);
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

  console.log(JSON.stringify(rsa));
}


exports.KeyGenerator = KeyGenerator;
