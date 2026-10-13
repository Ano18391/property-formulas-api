
const {
  getSql, bcrypt, crypto, prepare, send,
  validateUsername
} = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;

  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  try {
    const { username, recoveryCode } = req.body || {};

    if (
      !validateUsername(username) ||
      typeof recoveryCode !== "string" ||
      recoveryCode.length > 100
    ) {
      return send(res, 400, {
        error: "Enter your username and recovery code."
      });
    }

    const sql = getSql();

    const rows = await sql`
      SELECT id, username, recovery_code_hash
      FROM users
      WHERE username = ${username}
      LIMIT 1
    `;

    if (
      !rows.length ||
      !(await bcrypt.compare(
        recoveryCode,
        rows[0].recovery_code_hash
      ))
    ) {
      return send(res, 400, {
        error: "Invalid username or recovery code."
      });
    }

    const resetToken = crypto.randomBytes(32).toString("base64url");
    const tokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    await sql`
      UPDATE users
      SET reset_token_hash = ${tokenHash},
          reset_token_expires_at = NOW() + INTERVAL '10 minutes'
      WHERE id = ${rows[0].id}
    `;

    return send(res, 200, {
      message: "Recovery code accepted. Set a new password within 10 minutes.",
      resetToken
    });
  } catch (error) {
    console.error("Password recovery failed:", error.message);
    return send(res, 500, {
      error: "Could not verify the recovery code."
    });
  }
};
