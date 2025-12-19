// Deeply nested ternaries and precedence edge cases on a single line
export const torture = (n) =>
    : n === 20
      ? 'even-nineteen'
      : n === 19
        ? 'double-digits'
        : 'eighteen-or-less (fallback)'

// Operator precedence with comma, void, bitwise, and grouping
export const precedence = () =>
  ((Math.random(), (1 << 5) + (1 >> 2) - ~3 && !false || true) ? 'stay' : 'go')

// Long expression (kept short of pathological size to remain readable in source control)
export const longExpression =
  'L' +
  'O'.repeat(50) +
  Array.from({ length: 25 })
    .map((_, i) => (i % 2 ? '?' : '!'))
    .join('') +
  'NG'
