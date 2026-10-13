const { getSql, prepare, send, getSession } = require("../../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;

  if (req.method !== "POST") {
    return send(res, 405, { error: "Method not allowed." });
  }

  const session = getSession(req);
  if (!session) {
    return send(res, 401, { error: "Connectez-vous pour enregistrer un dossier." });
  }

  const body = req.body || {};
  const title = typeof body.title === "string" ? body.title.trim() : "";
  const data = body.propertyData;

  if (!title || title.length > 120) {
    return send(res, 400, { error: "Le titre doit contenir entre 1 et 120 caractères." });
  }

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return send(res, 400, { error: "Les données du bien sont invalides." });
  }

  let serialized;
  try {
    serialized = JSON.stringify(data);
    if (serialized.length > 50000) {
      return send(res, 400, { error: "Le dossier est trop volumineux." });
    }
  } catch {
    return send(res, 400, { error: "Les données du bien sont invalides." });
  }

  try {
    const sql = getSql();
    const requestedId = typeof body.id === "string" ? body.id.trim() : "";

    if (requestedId) {
      const rows = await sql`
        UPDATE property_dossiers
        SET title = ${title},
            property_data = ${serialized}::jsonb,
            updated_at = NOW()
        WHERE id = ${requestedId}
          AND user_id = ${session.userId}
        RETURNING id, title, property_data, created_at, updated_at
      `;

      if (!rows.length) {
        return send(res, 404, { error: "Dossier introuvable." });
      }

      return send(res, 200, { dossier: rows[0] });
    }

    const rows = await sql`
      INSERT INTO property_dossiers (user_id, title, property_data)
      VALUES (${session.userId}, ${title}, ${serialized}::jsonb)
      RETURNING id, title, property_data, created_at, updated_at
    `;

    return send(res, 201, { dossier: rows[0] });
  } catch (error) {
    console.error("Save property failed:", error.message);
    return send(res, 500, { error: "Impossible d'enregistrer le dossier." });
  }
};
