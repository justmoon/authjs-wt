
var rsa = {"d":"1a0d6735bce4612016432b8d8294747c25dc325bd46b5f91e3408f979cdba84b19227af05064032a0889d7ca7f3c9464fab60d2973dadde98a602a6e44bb7d31","phi":"c41261b1cdbb80a914acae0ec306e9164b450895c70fc1d492d3fc7a31400123ac33dc55786cc2ad34ad93b4f2731cdb2ac67e47c2fa866bb942589e7da4194c","a":"30eebafcf9e84f4f43cf5e21b99f32bc980b3d204e2d2de80b7d58333083de11f7111619f8dc5d04c83784987d3b8f59a6a7e7c71078362f77c58a4ab49710bd","e":"010001","n":"c41261b1cdbb80a914acae0ec306e9164b450895c70fc1d492d3fc7a314001256e08adccb978e31aceba5c4e3aac5f066661bde6f62966209dd909b712927375"};

var d = new BigInteger("00"+rsa.d, 16);
var e = new BigInteger("00"+rsa.e, 16);
var phi = new BigInteger("00"+rsa.phi, 16);
var a = new BigInteger("00"+rsa.a, 16);
var n = new BigInteger("00"+rsa.n, 16);

var phih = phi.shiftRight(1);
var phiq = phi.shiftRight(2);

var ONE = BigInteger.ONE;
var TWO = ONE.add(ONE);

d = phiq.add(ONE).shiftRight(1).multiply(e.modInverse(phiq)).mod(phiq);

// Encryption (c1 = 0)
var x = new BigInteger("123", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
x = new BigInteger("123942", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
x = new BigInteger("dc25a62aac5a50c5de76fc0118f81901", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
x = new BigInteger("afcced529aa665e70c85b3366863aeb22e7b157c5f2c03997", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
x = new BigInteger("cfdc7da8c3ddc0997d787a089e2ca092f0776304e7a12", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
x = new BigInteger("eb3899e7", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
x = new BigInteger("36a908f731540e47a187", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
x = new BigInteger("1", 16);
console.log("ENC =>", testenc(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");
console.log("SIG =>", testsig(x) ? "SUCCESS" : "FAIL", "("+x.toString(16)+")");

/*
// Encryption (c1 = 1)
x = new BigInteger("12345675", 16);
E = encrypt(x);
console.log("x =", x.toString(16));
console.log("jac", x.jacobi(n));
console.log("E =", E[0].toString(16));

x_ = decrypt(E);
console.log("x' =", x_.toString(16));

// Signing
var m = new BigInteger("1234588", 16);
var sig = m.modPow(d.shiftLeft(1), n);
console.log("m =", m.toString(16));
console.log("jac", m.jacobi(n));
console.log("sig =", sig.toString(16));
var v = sig.modPow(e, n);
console.log(v.compareTo(m) === 0 || v.compareTo(n.subtract(m)) === 0);
v = sig.add(1).modPow(e, n);
console.log(v.compareTo(m) !== 0 && v.compareTo(n.subtract(m)) !== 0);

m = new BigInteger("12345675", 16);
sig = m.multiply(a).modPow(d.shiftLeft(1), n);
console.log("m =", m.toString(16));
console.log("jac", m.jacobi(n));
console.log("sig =", sig.toString(16));
v = sig.modPow(e, n);
var m_ = m.multiply(a).mod(n);
console.log(v.compareTo(m_) === 0 || v.compareTo(n.subtract(m_)) === 0);

*/

function encrypt(x)
{
  var c1 = (x.compareTo(n.shiftRight(1)) < 0) ? 1 : 0;
  var c2 = (x.jacobi(n) === -1) ? 1 : 0;
  if (c2) {
    x = x.multiply(a);
  }
  return [x.modPow(e.shiftLeft(1), n), c1, c2];
}

function decrypt(E)
{
  var x = E[0].modPow(d, n);
  if (E[2]) {
    x = x.multiply(a.modInverse(n)).mod(n);
  }
  var c1 = (x.compareTo(n.shiftRight(1)) < 0) ? 1 : 0;
  if (c1 !== E[1]) {
    x = n.subtract(x);
  }
  return x;
}

function testenc(x)
{
  var E = encrypt(x);
  return x.compareTo(decrypt(E)) === 0;
}

function sign(m)
{
  var c = (x.jacobi(n) === -1) ? 1 : 0;
  if (c) {
    m = m.multiply(a);
  }
  return [m.modPow(d.shiftLeft(1), n), c];
}

function verify(m, S)
{
  var v = S[0].modPow(e, n);
  if (S[1]) {
    m = m.multiply(a).mod(n);
  }
  return v.equals(m) || v.equals(n.subtract(m));
}

function testsig(m)
{
  var S = sign(m);
  var S_ = S.slice(0);
  S_[0] = S_[0].add(ONE);
  return verify(m, S) && !verify(m, S_);
}
