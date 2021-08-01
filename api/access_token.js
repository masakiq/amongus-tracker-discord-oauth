const fetch = require('node-fetch');
const jwt = require('../src/jwt');
const crypto = require('../src/crypto');
const env = require('../src/env');

export default async (req, res) => {
  allowCors(req, res);
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  try {
    var token = req.body['token'];
    var clientId = req.body['client_id'];
    var clientSecret = req.body['client_secret'];
  } catch(err) {
    console.log(err);
    res.status(404).json({ error: 'invalid http method' });
    return;
  }

  var decoded = jwt.decode(token);
  if (decoded['errors'] != null) {
    var r = decoded['errors'].some(error => error == 'TokenExpiredError');
    if (r) {
      res.status(403).json({ error: 'server_token_expired' });
    } else {
      res.status(400).json({ error: 'bad_request' });
    }
    return;
  }
  if (decoded['typ'] != 'ecrypted_code') {
    res.status(403).json({ error: 'invalid_server_token' });
    return;
  }

  const ecryptedCode = decoded['sub'];
  const code = crypto.decrypt(ecryptedCode);
  if (!code) {
    res.status(403).json({ error: 'invalid_code' });
    return;
  }

  const redirectUri = getRedirectUri(req);
  requestDiscordToken(code, clientId, clientSecret, redirectUri).then(data => {
    data['expired_at'] = Math.floor(Date.now() / 1000) + data.expires_in;
    res.status(200).json(data);
  }).catch(err => {
    console.log(err);
    res.status(400).json('');
  });
}

const allowCors = (req, res) => {
  var allowUris = [];
  if (env.isDevelopment()) {
    allowUris.push('http://localhost:8080');
  } else {
    allowUris.push('https://client.amongus-tracker.com');
  }
  if (!allowUris.includes(req.headers.origin)) {
    return;
  }

  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );
}

const requestDiscordToken = async (code, clientId, clientSecret, redirectUri) => {
  const url = 'https://discord.com/api/v8/oauth2/token';
  const params = new URLSearchParams();
  params.append('client_id', clientId);
  params.append('client_secret', clientSecret);
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', redirectUri);

  const response = await fetch(url, {
    method: 'POST',
    body: params
  });
  const data = await response.json();
  return data;
}

const getRedirectUri = (req) => {
  const proto = req.headers['x-forwarded-proto'];
  const host = req.headers['x-forwarded-host'];
  return proto + '://' + host + '/api/callback';
}
