const jwt = require('jsonwebtoken');

module.exports = {
  encode: function (sub, aud, expired, typ) {
    const token = jwt.sign({
      exp: expired,
      sub: sub,
      iss: 'https://oauth.amongus-tracker.com',
      aud: aud,
      typ: typ
    }, this.privateKeyForJwt(), { algorithm: 'HS512' });
    return token;
  },
  decode: function (token) {
    var result = { errors: [] };
    var keys = this.privateKeyListForJwt();
    for (let i = 0; i < keys.length; i++) {
      var decoded = this.decodeWithKey(token, keys[i]);
      if (decoded['errors'] == null) {
        return decoded;
      } else {
        result['errors'].push(decoded['errors']);
      }
    }
    return result;
  },
  decodeWithKey: function (token, key) {
    try {
      var decoded = jwt.verify(
        token, key, { iss: 'https://oauth.amongus-tracker.com' }
      );
      return decoded;
    } catch(err) {
      var result = {};
      if (err instanceof jwt.TokenExpiredError) {
        return { errors: 'TokenExpiredError' };
      } else {
        // 未知のエラー
        return { errors: 'UnknownError' };
      }
    }
  },
  privateKeyForJwt: function () {
    const keys = this.privateKeyListForJwt();
    return keys[Math.floor(Math.random() * keys.length)];
  },
  privateKeyListForJwt: function () {
    return [
      process.env.PRIVATE_KEY_FOR_JWT_1,
      process.env.PRIVATE_KEY_FOR_JWT_2
    ];
  }
};
