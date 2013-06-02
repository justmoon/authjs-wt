// Full domain hash based on SHA512
function fdh(data, bytelen)
{
  var bitlen = bytelen << 3;

  if (typeof data === "string") {
    data = sjcl.codec.utf8String.toBits(data);
  }

  // Add hashing rounds until we exceed desired length in bits
  var counter = 0, output = [];
  while (sjcl.bitArray.bitLength(output) < bitlen) {
    var hash = sjcl.hash.sha512.hash(sjcl.bitArray.concat([counter], data));
    output = sjcl.bitArray.concat(output, hash);
    counter++;
  }

  // Truncate to desired length
  output = sjcl.bitArray.clamp(output, bitlen);

  return output;
}

jQuery(function ($) {
  $('form').submit(function () {
    var self = this,
        form = $(this);

    var rng = new SecureRandom();

    var username   = $(this.username).val(),
        secret     = $(this.secret  ).val(),
        server     = $(this).data('server'),
        exponent   = $(this).data('exponent'),
        modulus    = $(this).data('modulus'),
        alpha      = $(this).data('alpha'),
        iExponent  = new BigInteger(""+exponent, 16),
        iModulus   = new BigInteger(""+modulus, 16),
        iAlpha     = new BigInteger(""+alpha, 16);

    var publicInfo = "PAKDF_1_0_0:"+server.length+":"+server+
                     ":"+username.length+":"+username+":",
        publicSize = Math.ceil(Math.min((7+iModulus.bitLength()) >>> 3, 256)/8),
        publicHash = fdh(publicInfo, publicSize),
        publicHex  = sjcl.codec.hex.fromBits(publicHash),
        iPublic    = new BigInteger(""+publicHex, 16).setBit(0),
        secretInfo = publicInfo+":"+secret.length+":"+secret+":",
        secretSize = (7+iModulus.bitLength()) >>> 3,
        secretHash = fdh(secretInfo, secretSize),
        secretHex  = sjcl.codec.hex.fromBits(secretHash),
        iSecret    = new BigInteger(""+secretHex, 16).mod(iModulus);

    if (iSecret.jacobi(iModulus) !== 1) {
      iSecret = iSecret.multiply(iAlpha).mod(iModulus);
    }
    var iRandom;
    for (;;) {
      iRandom = new BigInteger(iModulus.bitLength(), rng);
      if (iRandom.compareTo(iModulus) < 0 && iRandom.jacobi(iModulus) === 1)
        break;
    }

    var iBlind     = iRandom.modPow(iPublic.multiply(iExponent), iModulus),
        iSignreq   = iSecret.multiply(iBlind).mod(iModulus),
        signreq    = iSignreq.toString(16);

    $(this.signreq).val(signreq);

    $.ajax({
      type: "POST",
      url: "/api/sign",
      data: {
        info: publicInfo,
        signreq: signreq
      },
      dataType: 'json',
      success: function (data) {
        $('#reply').show();

        // Reset
        $('#api_result').removeClass("alert-success").removeClass("alert-error");
        $('#signed_result').hide();
        if (data.result === "success") {
          var signresPretty = data.signres.match(/.{1,64}/g).join('<br>');
          $('#api_result').html("Blinded signature:<br>"+signresPretty).addClass('alert-success');
          $('#signed_result').show();

          var iSignres = new BigInteger(data.signres, 16);

          var iRandomInv = iRandom.modInverse(iModulus);

          var iSigned = iSignres.multiply(iRandomInv).mod(iModulus);

          $(self.signed).val(iSigned.toString(16));
        } else if (data.result === "error") {
          $('#api_result').text("Error: "+data.error_msg).addClass('alert-error');
        } else {
          $('#api_result').text("Unknown: "+JSON.stringify(data));
        }
        location.href = "#reply";
      }
    });
    return false;
  });
});
