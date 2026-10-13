const {
  getSql, bcrypt, prepare, send,
  validateUsername, setSessionCookie
} = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;
  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  try {
    const { username, password } = req.body || {};

    if (!validateUsername(username) || typeof password !== "string") {
      return send(res, 400, { error: "Enter your username and password." });
    }

    const sql = getSql();
    const rows = await sql`
      SELECT id, username, password_hash
      FROM users WHERE username = ${username}
      LIMIT 1
    `;

    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
      return send(res, 401, { error: "Incorrect username or password." });
    }

    setSessionCookie(res, rows[0]);

    return send(res, 200, {
      message: "Login successful.",
      user: { id: rows[0].id, username: rows[0].username }
    });
  } catch (error) {
    console.error("Login failed:", error.message);
    return send(res, 500, { error: "Could not log in." });
  }
};
