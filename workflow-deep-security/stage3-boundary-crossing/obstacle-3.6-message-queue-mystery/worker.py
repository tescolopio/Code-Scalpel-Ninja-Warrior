"""
=============================================================================
OBSTACLE 3.6: MESSAGE QUEUE MYSTERY (Consumer)
=============================================================================

PURPOSE: Test taint tracking from async message queue to SQL injection sink.
This worker consumes from Kafka and builds SQL with the message content.
Taint must flow: publisher.ts -> Kafka -> worker.py -> PostgreSQL

INTENTIONAL SQL INJECTION (DO NOT PARAMETERIZE):

1. Trusting Queue Content (line 41-42):
   - payload["comment"] and payload["userId"] come from Kafka
   - But that data originated from untrusted user input!
   - Message queue does NOT sanitize - it's just transport

2. SQL Injection via user_id (line 47):
   - user_id interpolated inside single quotes
   - Attacker can escape: ' OR '1'='1
   - Classic SQL injection vector

3. SQL Injection via comment (line 47):
   - comment uses dollar-quoting ($$ ... $$)
   - Attacker can escape: $$ ; DROP TABLE comments; $$
   - Dollar-quoting is NOT safe with user input!

4. Delayed Execution (entire worker):
   - This runs asynchronously, possibly hours later
   - Taint tracking must survive the time gap
   - Original request context is lost

EXPECTED BEHAVIOR (PASS):
- Track taint FROM publisher.ts through Kafka TO this consumer
- Detect SQL injection in cur.execute()
- Understand async message queues preserve taint
- Flag both user_id and comment as tainted

FAILURE MODE (ELIMINATION):
- Losing taint at async queue boundary
- Missing cross-service data flow
- Trusting message queue content as safe
- Only analyzing within single codebase
=============================================================================
"""
# INTENTIONAL: Vulnerable sink for Code Scalpel to catch - do not parameterize!
import json
import psycopg2
from kafka import KafkaConsumer

consumer = KafkaConsumer('comments', bootstrap_servers=['kafka:9092'])
conn = psycopg2.connect("dbname=demo user=demo password=demo")


def handle_message(message):
    """INTENTIONAL: SQL injection via message queue content."""
    payload = json.loads(message.value)
    comment = payload["comment"]   # TAINTED: From publisher.ts via Kafka
    user_id = payload["userId"]    # TAINTED: From publisher.ts via Kafka

    with conn.cursor() as cur:
        # VULNERABILITY: SQL injection via both user_id AND comment!
        # user_id in single quotes - can escape with '
        # comment in dollar quotes - can escape with $$
        cur.execute(f"INSERT INTO comments(user_id, body) VALUES ('{user_id}', $$ {comment} $$)")
        conn.commit()


for msg in consumer:
    try:
        handle_message(msg)
    except Exception as exc:
        # Minimal handling to keep the intentionally vulnerable worker alive for analysis.
        print(f"worker error: {exc}")
