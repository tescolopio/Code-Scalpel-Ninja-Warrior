/*
 * =============================================================================
 * OBSTACLE 3.6: MESSAGE QUEUE MYSTERY (Publisher)
 * =============================================================================
 *
 * PURPOSE: Test taint tracking across asynchronous message queue boundaries.
 * Tainted data published to Kafka must be tracked to consumers, even though
 * the consumer is a separate process that runs later.
 *
 * INTENTIONAL TAINT PUBLICATION (DO NOT SANITIZE):
 *
 * 1. User-Controlled Comment (line 32):
 *    - rawComment is tainted user input
 *    - Published to Kafka WITHOUT any validation or sanitization
 *    - Crosses async boundary to unknown consumers
 *
 * 2. User-Controlled Key (line 30):
 *    - userId is also user-controlled
 *    - Used as message key - can affect partitioning
 *    - May be logged/displayed by Kafka admin tools
 *
 * 3. JSON Serialization (line 31-36):
 *    - Tainted data serialized into JSON message value
 *    - Consumer will deserialize and use this data
 *    - worker.py consumes this and builds SQL!
 *
 * EXPECTED BEHAVIOR (PASS):
 * - Track taint INTO the message queue
 * - Understand queue is async boundary to other services
 * - Mark queue consumers as receiving tainted data
 * - Cross-service taint tracking
 *
 * FAILURE MODE (ELIMINATION):
 * - Losing taint at async message boundary
 * - Assuming queue sanitizes data
 * - Only tracking within single service/process
 * - Missing the connection to worker.py consumer
 * =============================================================================
 */
// INTENTIONAL: Tainted data published without validation - consumer (worker.py) is vulnerable
import { Kafka } from 'kafkajs'

const kafka = new Kafka({ clientId: 'web', brokers: ['kafka:9092'] })
const producer = kafka.producer()

export async function publishComment(userId: string, rawComment: string) {
  """INTENTIONAL: Publish tainted user input to Kafka without any validation."""
  await producer.connect()
  await producer.send({
    topic: 'comments',
    messages: [
      {
        key: userId,  // TAINTED: User-controlled key
        value: JSON.stringify({
          userId,
          comment: rawComment,  // CRITICAL: Untrusted data crossing async boundary!
          at: Date.now()
        })
      }
    ]
  })
  await producer.disconnect()
}
