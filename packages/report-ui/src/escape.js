/** Mirror of Rust escape rules for frontend XSS regression tests. */
export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function stripAnsi(s) {
  return String(s).replace(/\u001b\[[0-9;]*[a-zA-Z]/g, "");
}

export function sanitizeLog(s) {
  return escapeHtml(stripAnsi(s));
}
