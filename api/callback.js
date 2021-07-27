const jwt = require('../src/jwt');
const crypto = require('../src/crypto');

export default async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  const cookie = req.cookies['state'];

  var decoded = jwt.decode(cookie);
  if (decoded['errors'] != null) {
    var r = decoded['errors'].some(error => error == 'TokenExpiredError');
    if (r) {
      res.redirect('https://amongus-tracker.com?error=server_token_expired');
    } else {
      res.redirect('https://amongus-tracker.com?error=bad_request');
    }
    return;
  }

  if (decoded['typ'] != 'state') {
    res.redirect(decoded['aud'] + '?error=invalid_server_token');
    return;
  }
  if (state != decoded['sub']) {
    res.redirect(decoded['aud'] + '?error=invalid_state');
    return;
  }

  const ecryptedCode = crypto.encrypt(code);
  const expired = Math.floor(Date.now() / 1000) + 10;
  const token = jwt.encode(ecryptedCode, decoded['aud'], expired, 'ecrypted_code');

  const redirectUrl = `${decoded['aud']}?token=${token}&state=${state}`;
  res.redirect(redirectUrl);
}