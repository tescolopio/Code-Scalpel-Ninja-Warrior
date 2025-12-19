const admin = 'ascii-admin'
const аdmin = 'cyrillic-admin' // first character is U+0430 CYRILLIC SMALL LETTER A

const user\u200dname = 'contains zero width joiner'
const label = `rtl marker: \u202E}\u202C`

// Homoglyph shadowing should be detected even though the names look identical
export function normalizeUser(input) {
  const 𝛂lpha = input?.trim?.() ?? input // mixed-script identifier
  return {
    admin,
    shadow: аdmin,
    user\u200dname,
    label,
    𝛂lpha,
  }
}

// Comment hiding with bidi controls: \u202E } ; { \u202C
