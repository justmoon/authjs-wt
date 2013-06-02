
var Signer = require('../lib/signer').Signer;

var signer = new Signer();

exports.sign = function(req, res, next){
  var signres;
  try {
    signres = signer.sign(""+req.body.info, ""+req.body.signreq);
  } catch (e) {
    next(e);
    return;
  }
  var data = {
    result: 'success',
    signres: signres
  };
  res.send(JSON.stringify(data));
};
