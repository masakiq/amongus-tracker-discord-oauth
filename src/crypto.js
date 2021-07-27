const crypto = require('crypto-js');

module.exports = {
  encrypt: function (value) {
    return crypto.AES.encrypt(value, this.privateKeyForAes()).toString();
  },
  decrypt: function (value) {
    var keys = this.privateKeyListForAes();
    for (let i = 0; i < keys.length; i++) {
      const decrypted = this.decryptWithKey(value, keys[i]);
      if (decrypted) {
        return decrypted;
      }
    }
  },
  decryptWithKey: function (value, key) {
    try {
      const bytes  = crypto.AES.decrypt(value, key);
      const decrypted = bytes.toString(crypto.enc.Utf8);
      if (decrypted) {
        return decrypted;
      }
    } catch(err) {}
  },
  privateKeyForAes: function () {
    const keys = this.privateKeyListForAes();
    return keys[Math.floor(Math.random() * keys.length)];
  },
  privateKeyListForAes: function () {
    return [
      process.env.PRIVATE_KEY_FOR_AES_1,
      process.env.PRIVATE_KEY_FOR_AES_2
    ];
  }
};
