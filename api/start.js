const jwt = require('../src/jwt');
const env = require('../src/env');

module.exports = (req, res) => {
  const aud = decodeURIComponent(req.query.aud);
  const state = req.query.state;
  const clientId = req.query.client_id;

  if (!verifyAud(aud)) {
    res.redirect('https://amongus-tracker.com');
    return;
  }
  if (!verifyState(state)) {
    res.redirect(aud + '?error=invalid_state');
    return;
  }
  if (!verifyClientId(clientId)) {
    res.redirect(aud + '?error=invalid_client_id');
    return;
  }

  const expired = Math.floor(Date.now() / 1000) + (60 * 10);
  const token = jwt.encode(state, aud, expired, 'state');

  const expiredDateTime = new Date(expired * 1000);
  const secure = aud.includes('localhost') ? '' : 'Secure;';
  res.setHeader('Set-Cookie', [`state=${token}; Expires=${expiredDateTime}; ${secure} SameSite=Lax; HttpOnly`]);

  const callbackUrl = generateCallbackUrl(req);
  const authUrl = generateAuthUrl(clientId, state, callbackUrl);
  res.redirect(authUrl);
};

const verifyState = (state) => {
  return state && state.length >= 10;
}

const verifyAud = (aud) => {
  var allowed = [];
  allowed.push('http://localhost:6474/oauth/callback');
  return allowed.includes(aud);
}

const verifyClientId = (clientId) => {
  return clientId && clientId.length == 18 && clientId.match(/^\d*$/);
}

const generateCallbackUrl = (req) => {
  const proto = req.headers['x-forwarded-proto'];
  const host = req.headers['x-forwarded-host'];
  return proto + '://' + host + '/api/callback';
}

const generateAuthUrl = (clientId, state, callbackUrl) => {
  return `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&response_type=code&scope=rpc&state=${state}`;
}
