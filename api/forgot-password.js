const {
  getSql, bcrypt, prepare, send,
  validateUsername, signToken
} = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;
  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  try {
    const { username, recoveryCode } = req.body || {};

    if (!validateUsername(username) || typeof recoveryCode !== "string") {
      return send(res, 400, { error: "Enter your username and recovery code." });
    }

    const sql = getSql();
    const rows = await sql`
      SELECT id, username, recovery_code_hash
      FROM users WHERE username = ${username}
      LIMIT 1
    `;

    if (!rows.length ||
      !(await bcrypt.compare(recoveryCode, rows[0].recovery_code_hash))) {
      return send(res, 400, { error: "Invalid username or recovery code." });
    }

    const resetToken = signToken({
      purpose: "password_reset",
      userId: rows[0].id,
      username: rows[0].username,
      duration: 10 * 60
    });

    return send(res, 200, {
      message: "Recovery code accepted. Set a new password within 10 minutes.",
      resetToken
    });
  } catch (error) {
    console.error("Password recovery failed:", error.message);
    return send(res, 500, { error: "Could not verify the recovery code." });
  }
};
