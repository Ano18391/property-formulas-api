const { prepare, send, clearSessionCookie } = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;
  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  clearSessionCookie(res);
  return send(res, 200, { message: "Logged out." });
};
