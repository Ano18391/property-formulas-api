const { getSql, prepare, send, getSession } = require("../../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;

  if (req.method !== "GET") {
    return send(res, 405, { error: "Method not allowed." });
  }

  const session = getSession(req);
  if (!session) {
    return send(res, 401, { error: "Connectez-vous pour accéder à vos dossiers." });
  }

  try {
    const sql = getSql();
    const rows = await sql`
      SELECT id, title, property_data, created_at, updated_at
      FROM property_dossiers
      WHERE user_id = ${session.userId}
      ORDER BY updated_at DESC
    `;

    return send(res, 200, { dossiers: rows });
  } catch (error) {
    console.error("List properties failed:", error.message);
    return send(res, 500, { error: "Impossible de charger les dossiers." });
  }
};
