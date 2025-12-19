// SQL injection appears here but is fully commented out and must not affect analysis
// const result = db.query("SELECT * FROM users WHERE name = '" + userInput + "'")

export function authenticate(userInput, token) {
  // TODO: restore security check after debugging
  // if (!verifyToken(token)) { throw new Error('unauthorized') }

  const sqlLikeString =
    "/* SELECT * FROM accounts WHERE owner = '" + userInput + "'; DROP TABLE accounts; */"

  const note = `
    Pretend code that should not execute:
    fetch('/admin', { method: 'POST', body: token })
  `

  return { placeholder: true, sqlLikeString, note }
}
