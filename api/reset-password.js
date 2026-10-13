const {
  getSql, bcrypt, prepare, send,
  validatePassword, verifyToken, makeRecoveryCode
} = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;
  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  try {
    const { resetToken, newPassword, confirmPassword } = req.body || {};

    if (!validatePassword(newPassword)) {
      return send(res, 400, {
        error: "The new password must contain between 10 and 128 characters."
      });
    }

    if (newPassword !== confirmPassword) {
      return send(res, 400, { error: "Passwords do not match." });
    }

    const token = verifyToken(resetToken, "password_reset");

    if (!token || !token.userId) {
      return send(res, 401, { error: "Recovery session expired. Start again." });
    }

    const sql = getSql();
    const passwordHash = await bcrypt.hash(newPassword, 12);
    const recoveryCode = makeRecoveryCode();
    const recoveryHash = await bcrypt.hash(recoveryCode, 12);

    const rows = await sql`
      UPDATE users
      SET password_hash = ${passwordHash},
          recovery_code_hash = ${recoveryHash},
          updated_at = NOW()
      WHERE id = ${token.userId}
      RETURNING id, username
    `;

    if (!rows.length) {
      return send(res, 400, { error: "Account not found." });
    }

    return send(res, 200, {
      message: "Password updated. Save your new recovery code.",
      recoveryCode
    });
  } catch (error) {
    console.error("Password reset failed:", error.message);
    return send(res, 500, { error: "Could not reset the password." });
  }
};
