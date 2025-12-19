// This file intentionally contains a syntax error (missing closing brace/paren)
export function partial(items) {
  const ready = items.filter((item) => item?.ready === true)
  if (!ready.length) {
    return null
  // <- missing closing brace for the function
