/*
 * =============================================================================
 * OBSTACLE 3.4: REST/GraphQL/gRPC PROTOCOL MAZE
 * =============================================================================
 *
 * PURPOSE: Test taint tracking across multiple protocol boundaries.
 * Data flows: GraphQL -> REST -> gRPC and back - taint must be preserved
 * across ALL protocol hops, regardless of serialization format.
 *
 * INTENTIONAL VULNERABILITIES (DO NOT SANITIZE):
 *
 * 1. GraphQL Entry Point (line 37-38):
 *    - `note` parameter is user-controlled (attacker input)
 *    - GraphQL does NOT sanitize - passes through unchanged
 *
 * 2. REST Microservice Hop (line 40-45):
 *    - Tainted `note` sent via REST POST body
 *    - JSON.stringify() preserves the tainted value
 *    - REST service receives unsanitized data
 *
 * 3. gRPC Service Hop (line 47-49):
 *    - Same tainted `note` forwarded as user_note in gRPC
 *    - Protocol boundary MUST NOT cleanse taint
 *    - gRPC service also receives unsanitized data
 *
 * 4. XSS Return Path (line 54):
 *    - Tainted note returned directly to GraphQL caller
 *    - Enables stored/reflected XSS if rendered in browser
 *    - Full round-trip taint flow
 *
 * EXPECTED BEHAVIOR (PASS):
 * - Track taint across GraphQL -> REST boundary
 * - Track taint across REST -> gRPC boundary
 * - Track taint through return path
 * - Flag XSS risk in returned note field
 * - NOT lose taint at protocol transitions
 *
 * FAILURE MODE (ELIMINATION):
 * - Losing taint at any protocol boundary
 * - Assuming serialization sanitizes data
 * - Missing the XSS vector in return value
 * - Only tracking within single protocol
 * =============================================================================
 */
// INTENTIONALLY INSECURE - DO NOT USE IN PRODUCTION
import express from 'express'
import { buildSchema } from 'graphql'
import { graphqlHTTP } from 'express-graphql'
import fetch from 'node-fetch'
import { InventoryClient } from './inventory_grpc_stub' // placeholder for generated client

const app = express()
const schema = buildSchema(`
  type Query { product(id: ID!, note: String): Product }
  type Product { id: ID!, name: String!, price: Int!, note: String }
`)

const root = {
  product: async ({ id, note }: { id: string; note?: string }) => {
    // VULNERABILITY 1: Send untrusted note into REST microservice.
    // Taint flows: GraphQL -> REST (JSON body)
    await fetch(`http://rest-microservice.local/products/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userNote: note })  // TAINTED
    })

    // VULNERABILITY 2: Forward the same note into gRPC without sanitization.
    // Taint flows: GraphQL -> gRPC (protocol buffer)
    const client = new InventoryClient('inventory:50051', null)
    const grpcResponse = await client.getProduct({ id, user_note: note })  // TAINTED

    return {
      id: grpcResponse.id,
      name: grpcResponse.name,
      price: grpcResponse.price_cents,
      // VULNERABILITY 3: Tainted note returned directly to caller - XSS vector!
      note // DANGER: Enables stored/reflected XSS if rendered
    }
  }
}

app.use(
  '/graphql',
  graphqlHTTP({
    schema,
    rootValue: root,
    graphiql: true
  })
)

app.listen(4000, () => {
  console.log('GraphQL torture-test gateway running on port 4000 (INTENTIONALLY INSECURE - DO NOT USE IN PRODUCTION)')
})
