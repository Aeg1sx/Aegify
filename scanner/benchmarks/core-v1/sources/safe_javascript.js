/** Owned negative controls paired with the JavaScript positive controls. */

export function safeSql(req, db) {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}

export function safeFixedOriginRequest(req) {
  const owner = req.query.owner;
  return fetch(`https://api.github.com/repos/${owner}`);
}
