/*
 * =============================================================================
 * OBSTACLE 3.2: SCHEMA DRIFT (Consumer)
 * =============================================================================
 *
 * PURPOSE: Demonstrate schema version mismatch across service boundaries.
 * The producer sends v2 payloads but the consumer only understands v1.
 * This causes SILENT DATA LOSS and TYPE COERCION ERRORS.
 *
 * INTENTIONAL PROBLEMS (DO NOT UPDATE TO V2):
 *
 * 1. Type/Schema Mismatch (line 27-29):
 *    - OrderV1 expects totalCents: number
 *    - v2 producer sends totalCents: "1899" (STRING!)
 *    - Type definition lies about runtime reality
 *
 * 2. Silent String-to-Number Coercion (line 34):
 *    - Number(data.totalCents) coerces string to number
 *    - No validation that the coercion succeeded
 *    - Becomes NaN on unexpected formats ("$18.99", "N/A", etc.)
 *
 * 3. Lost Fields (not in code - see producer_v2_payload.json):
 *    - v2 adds: currency, lineItems[], shipping{}
 *    - Consumer IGNORES all these fields completely
 *    - Critical business data silently discarded
 *
 * 4. Unsafe Type Assertion (line 31):
 *    - `as Record<string, unknown>` trusts input structure
 *    - No runtime validation of field presence or types
 *
 * EXPECTED BEHAVIOR (PASS):
 * - Detect schema drift between producer and consumer
 * - Flag NaN risk from string-to-number coercion
 * - Identify silently dropped fields
 * - Reduce confidence at JSON deserialization boundaries
 *
 * FAILURE MODE (ELIMINATION):
 * - Trusting the v1 type definition matches actual payloads
 * - Missing the string->number coercion issue
 * - Not detecting lost v2 fields
 * =============================================================================
 */
// INTENTIONAL: Consumer stuck on schema v1 - does NOT understand v2 payloads!
type OrderV1 = {
  orderId: string
  totalCents: number  // v2 sends this as STRING - silent type drift!
}

export function parseV1(body: unknown): OrderV1 {
  // VULNERABILITY: Unsafe type assertion - no runtime validation
  const data = body as Record<string, unknown>

  // DANGER: v2 sends totalCents as a string, but the v1 consumer coerces without validation.
  // Number("1899") works, but Number("$18.99") or Number("N/A") becomes NaN!
  const coercedTotal = Number(data.totalCents)

  return {
    orderId: String(data.orderId),
    totalCents: coercedTotal // SILENT ERROR: becomes NaN on unexpected formats
  }
}

// INTENTIONAL: Fields added in v2 (currency, lineItems, shipping) are IGNORED completely.
// Schema drift should be detected as potential silent data loss and type confusion.
