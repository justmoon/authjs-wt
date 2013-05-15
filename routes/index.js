var pkg = require('../package.json');

var config = require('../config.js');

/*
 * GET home page.
 */

exports.index = function(req, res){
  res.render('index', {
    title: 'Auth.js Peer Version ' + pkg.version,
    modulus: config.rsa.n,
    exponent: config.rsa.e
  });
};

