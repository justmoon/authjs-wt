jQuery(function ($) {
  $('form').submit(function () {
    var self = this,
        form = $(this);

    var rng = new SecureRandom();

    var username   = $(this.username).val(),
        secret     = $(this.secret  ).val(),
        exponent   = $(this).data('exponent'),
        modulus    = $(this).data('modulus'),
        iExponent  = new BigInteger(""+exponent, 16),
        iModulus   = new BigInteger(""+modulus, 16);

    var secretHash = sjcl.hash.sha256.hash(secret),
        secretHex  = sjcl.codec.hex.fromBits(secretHash),
        iSecret    = new BigInteger(secretHex, 16),
        iRandom    = new BigInteger(512, rng),
        iSignreq   = iRandom.modPow(iExponent, iModulus)
                       .multiply(iSecret).mod(iModulus),
        signreq    = iSignreq.toString(16);

    $(this.signreq).val(signreq);

    $.ajax({
      type: "POST",
      url: "/api/sign",
      data: {
        username: username,
        signreq: signreq
      },
      dataType: 'json',
      success: function (data) {
        $('#reply').show();

        // Reset
        $('#api_result').removeClass("alert-success").removeClass("alert-error");
        $('#signed_result').hide();
        if (data.result === "success") {
          var signresPretty = data.signres.match(/.{64}/g).join('<br>');
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
