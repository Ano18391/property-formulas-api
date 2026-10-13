
const {
  getSql, bcrypt, crypto, prepare, send,
  validatePassword, makeRecoveryCode
} = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;

  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  try {
    const { resetToken, newPassword, confirmPassword } = req.body || {};

    if (typeof resetToken !== "string" || resetToken.length > 200) {
      return send(res, 401, {
        error: "Recovery session expired. Start again."
      });
    }

    if (!validatePassword(newPassword)) {
      return send(res, 400, {
        error: "The new password must contain between 10 and 128 characters."
      });
    }

    if (newPassword !== confirmPassword) {
      return send(res, 400, {
        error: "Passwords do not match."
      });
    }

    const tokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    const passwordHash = await bcrypt.hash(newPassword, 12);
    const recoveryCode = makeRecoveryCode();
    const recoveryHash = await bcrypt.hash(recoveryCode, 12);

    const sql = getSql();

    const rows = await sql`
      UPDATE users
      SET password_hash = ${passwordHash},
          recovery_code_hash = ${recoveryHash},
          reset_token_hash = NULL,
          reset_token_expires_at = NULL,
          updated_at = NOW()
      WHERE reset_token_hash = ${tokenHash}
        AND reset_token_expires_at > NOW()
      RETURNING id, username
    `;

    if (!rows.length) {
      return send(res, 401, {
        error: "Recovery session expired or already used. Start again."
      });
    }

    return send(res, 200, {
      message: "Password updated. Save your new recovery code.",
      recoveryCode
    });
  } catch (error) {
    console.error("Password reset failed:", error.message);
    return send(res, 500, {
      error: "Could not reset the password."
    });
  }
};
