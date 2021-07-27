module.exports = {
  type: function () {
    return process.env.ENV_TYPE;
  },
  isDevelopment: function () {
    return process.env.ENV_TYPE == 'development';
  }
};
