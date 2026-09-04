/** Owned positive controls for JavaScript data-flow rules. */

export function unsafeSql(req, db) {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id = " + id);
}

export function unsafeSsrf(req) {
  const target = req.query.url;
  return fetch(target);
}
