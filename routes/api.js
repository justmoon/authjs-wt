
var Signer = require('../lib/signer').Signer;

var signer = new Signer();

exports.sign = function(req, res){
  var data = {
    result: 'success',
    signres: signer.sign(req.body.signreq)
  };
  res.send(JSON.stringify(data));
};
