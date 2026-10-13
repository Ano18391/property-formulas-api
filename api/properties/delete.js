const { getSql, prepare, send, getSession } = require("../../lib/auth");

module.exports = async function handler(req, res) {
  if (prepare(req, res)) return;

  if (req.method !== "DELETE") {
    return send(res, 405, { error: "Method not allowed." });
  }

  const session = getSession(req);

  if (!session) {
    return send(res, 401, {
      error: "Connectez-vous pour supprimer un dossier."
    });
  }

  const id =
    typeof req.query?.id === "string"
      ? req.query.id.trim()
      : "";

  if (!id) {
    return send(res, 400, {
      error: "Identifiant du dossier manquant."
    });
  }

  try {
    const sql = getSql();

    const rows = await sql`
      DELETE FROM property_dossiers
      WHERE id = ${id}
        AND user_id = ${session.userId}
      RETURNING id
    `;

    if (!rows.length) {
      return send(res, 404, {
        error: "Dossier introuvable ou accès refusé."
      });
    }

    return send(res, 200, {
      success: true,
      message: "Dossier supprimé."
    });
  } catch (error) {
    console.error("Delete property failed:", error.message);

    return send(res, 500, {
      error: "Impossible de supprimer le dossier."
    });
  }
};
