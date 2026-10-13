const { prepare, send, getSession } = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;
  if (req.method !== "GET") {
    return send(res, 405, { error: "Method not allowed." });
  }

  const session = getSession(req);

  if (!session) {
    return send(res, 401, { error: "Not logged in." });
  }

  return send(res, 200, {
    user: { id: session.userId, username: session.username }
  });
};
