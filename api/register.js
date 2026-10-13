const {
  getSql, bcrypt, prepare, send,
  validateUsername, validatePassword,
  makeRecoveryCode, setSessionCookie
} = require("../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;
  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  try {
    const { username, password, confirmPassword } = req.body || {};

    if (!validateUsername(username)) {
      return send(res, 400, {
        error: "The username must contain 3–24 letters, numbers, dots, underscores or hyphens."
      });
    }

    if (!validatePassword(password)) {
      return send(res, 400, {
        error: "The password must contain between 10 and 128 characters."
      });
    }

    if (password !== confirmPassword) {
      return send(res, 400, { error: "Passwords do not match." });
    }

    const sql = getSql();
    const passwordHash = await bcrypt.hash(password, 12);
    const recoveryCode = makeRecoveryCode();
    const recoveryHash = await bcrypt.hash(recoveryCode, 12);

    const rows = await sql`
      INSERT INTO users (username, password_hash, recovery_code_hash)
      VALUES (${username}, ${passwordHash}, ${recoveryHash})
      RETURNING id, username
    `;

    setSessionCookie(res, rows[0]);

    return send(res, 201, {
      message: "Account created. Save your recovery code now.",
      user: { id: rows[0].id, username: rows[0].username },
      recoveryCode
    });
  } catch (error) {
    if (error.code === "23505") {
      return send(res, 409, { error: "This exact username is already taken." });
    }

    console.error("Registration failed:", error.message);
    return send(res, 500, { error: "Could not create the account." });
  }
};
