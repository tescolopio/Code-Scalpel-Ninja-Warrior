/**
 * =============================================================================
 * ADVANCED ASYNC PATTERN TAINT TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation through advanced asynchronous patterns
 * in JavaScript/Node.js where taint tracking becomes challenging.
 *
 * CRITICAL SCENARIOS:
 * 1. Promise chains and composition
 * 2. Async generators and iterators
 * 3. Observable patterns (RxJS-style)
 * 4. Worker threads and message passing
 * 5. Stream pipelines
 * 6. Event loop timing attacks
 *
 * =============================================================================
 */

const { exec, execSync } = require('child_process');
const fs = require('fs');
const { EventEmitter } = require('events');
const { Readable, Writable, Transform, pipeline } = require('stream');
const { promisify } = require('util');

// =============================================================================
// PROMISE CHAIN TAINT TESTS
// =============================================================================

class PromiseChainTaintTests {
    /**
     * VULNERABILITY: Simple promise chain preserves taint
     */
    simpleChain(userInput) {
        // TAINT SOURCE
        return Promise.resolve(userInput)
            .then(x => x.toUpperCase())
            .then(x => x.trim())
            .then(x => {
                // TAINT SINK: SQL Injection after chain
                const query = `SELECT * FROM t WHERE x = '${x}'`;
                console.log(query); // VULNERABILITY
                return x;
            });
    }

    /**
     * VULNERABILITY: Promise.all preserves taint in all elements
     */
    promiseAllTaint(inputs) {
        // TAINT SOURCE: Array of tainted inputs
        const promises = inputs.map(input =>
            Promise.resolve(input).then(x => x.toLowerCase())
        );

        return Promise.all(promises).then(results => {
            // TAINT SINK: Each result is tainted
            results.forEach(r => {
                exec(`echo ${r}`); // VULNERABILITY
            });
            return results;
        });
    }

    /**
     * VULNERABILITY: Promise.race preserves winner's taint
     */
    promiseRaceTaint(inputs) {
        // TAINT SOURCE
        const promises = inputs.map((input, i) =>
            new Promise(resolve =>
                setTimeout(() => resolve(input), i * 100)
            )
        );

        return Promise.race(promises).then(winner => {
            // TAINT SINK: Winner is tainted
            fs.writeFileSync(winner, 'data'); // VULNERABILITY
            return winner;
        });
    }

    /**
     * VULNERABILITY: Promise.allSettled preserves taint in fulfilled values
     */
    promiseAllSettledTaint(inputs) {
        // TAINT SOURCE
        const promises = inputs.map(input =>
            Math.random() > 0.5
                ? Promise.resolve(input)
                : Promise.reject(new Error(input))
        );

        return Promise.allSettled(promises).then(results => {
            results.forEach(result => {
                if (result.status === 'fulfilled') {
                    // TAINT SINK: Fulfilled value is tainted
                    const query = `INSERT INTO log VALUES ('${result.value}')`;
                    console.log(query); // VULNERABILITY
                } else {
                    // Error message might also contain taint
                    console.log(`Error: ${result.reason.message}`); // VULNERABILITY
                }
            });
        });
    }

    /**
     * VULNERABILITY: Promise.any preserves first successful taint
     */
    promiseAnyTaint(inputs) {
        // TAINT SOURCE
        const promises = inputs.map((input, i) =>
            i === 0
                ? Promise.reject(new Error('first fails'))
                : Promise.resolve(input)
        );

        return Promise.any(promises).then(value => {
            // TAINT SINK: First success is tainted
            exec(value); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: Nested promise chains
     */
    nestedChainsTaint(userInput) {
        // TAINT SOURCE
        return Promise.resolve(userInput)
            .then(outer => {
                return Promise.resolve(outer)
                    .then(inner => {
                        return Promise.resolve(inner)
                            .then(deepest => {
                                // TAINT SINK: Deep nesting preserves taint
                                return execSync(`echo ${deepest}`).toString(); // VULNERABILITY
                            });
                    });
            });
    }

    /**
     * VULNERABILITY: Promise with finally
     */
    promiseFinallyTaint(userInput) {
        let captured = null;

        return Promise.resolve(userInput)
            .then(x => {
                captured = x; // Taint captured in closure
                return x;
            })
            .finally(() => {
                // TAINT SINK: Captured value in finally
                if (captured) {
                    fs.appendFileSync(captured, 'log'); // VULNERABILITY
                }
            });
    }
}

// =============================================================================
// ASYNC/AWAIT TAINT TESTS
// =============================================================================

class AsyncAwaitTaintTests {
    /**
     * VULNERABILITY: Async function preserves taint
     */
    async simpleAsyncTaint(userInput) {
        // TAINT SOURCE
        const step1 = await Promise.resolve(userInput);
        const step2 = await this.transformAsync(step1);
        const step3 = await this.formatAsync(step2);

        // TAINT SINK: Still tainted after multiple awaits
        exec(step3); // VULNERABILITY
    }

    async transformAsync(data) {
        await new Promise(r => setTimeout(r, 10));
        return data.toUpperCase(); // STILL TAINTED
    }

    async formatAsync(data) {
        await new Promise(r => setTimeout(r, 10));
        return `[${data}]`; // STILL TAINTED
    }

    /**
     * VULNERABILITY: Try/catch with async doesn't sanitize
     */
    async tryCatchAsyncTaint(userInput) {
        try {
            // TAINT SOURCE
            const result = await Promise.resolve(userInput);
            // TAINT SINK: Inside try block
            const query = `SELECT * FROM t WHERE x = '${result}'`;
            console.log(query); // VULNERABILITY
        } catch (error) {
            // Error might contain tainted data
            console.log(`Error: ${error.message}`); // POTENTIAL VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Async loop preserves taint per iteration
     */
    async asyncLoopTaint(items) {
        // TAINT SOURCE: Array of tainted items
        for (const item of items) {
            const processed = await Promise.resolve(item.toUpperCase());
            // TAINT SINK: Each iteration is vulnerable
            exec(`process ${processed}`); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Parallel async with map
     */
    async parallelAsyncTaint(items) {
        // TAINT SOURCE
        const results = await Promise.all(
            items.map(async item => {
                await new Promise(r => setTimeout(r, 10));
                return item.toLowerCase();
            })
        );

        // TAINT SINK: All parallel results are tainted
        results.forEach(r => {
            fs.writeFileSync(`/tmp/${r}`, 'data'); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: Async IIFE captures taint
     */
    asyncIifeTaint(userInput) {
        // TAINT SOURCE captured in IIFE
        (async () => {
            const data = await Promise.resolve(userInput);
            // TAINT SINK: Inside IIFE
            const query = `INSERT INTO t VALUES ('${data}')`;
            console.log(query); // VULNERABILITY
        })();
    }

    /**
     * VULNERABILITY: Conditional async branches
     */
    async conditionalAsyncTaint(userInput, condition) {
        // TAINT SOURCE
        let result;
        if (condition) {
            result = await Promise.resolve(userInput.toUpperCase());
        } else {
            result = await Promise.resolve(userInput.toLowerCase());
        }
        // Both branches preserve taint
        // TAINT SINK
        exec(result); // VULNERABILITY
    }
}

// =============================================================================
// ASYNC GENERATOR TAINT TESTS
// =============================================================================

class AsyncGeneratorTaintTests {
    /**
     * VULNERABILITY: Async generator yields preserve taint
     */
    async *taintedGenerator(items) {
        // TAINT SOURCE: Tainted items
        for (const item of items) {
            await new Promise(r => setTimeout(r, 10));
            yield item.toUpperCase(); // Each yield is TAINTED
        }
    }

    async consumeGenerator(items) {
        for await (const value of this.taintedGenerator(items)) {
            // TAINT SINK: Each yielded value is tainted
            exec(`process ${value}`); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Async generator with transform
     */
    async *transformGenerator(source, transformer) {
        for await (const item of source) {
            yield transformer(item); // Taint flows through transformer
        }
    }

    async useTransformGenerator(taintedItems) {
        const source = this.taintedGenerator(taintedItems);
        const transformed = this.transformGenerator(source, x => `[${x}]`);

        for await (const value of transformed) {
            // TAINT SINK: Transformed values are tainted
            const query = `INSERT INTO log VALUES ('${value}')`;
            console.log(query); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Async generator composition
     */
    async *filterGenerator(source, predicate) {
        for await (const item of source) {
            if (predicate(item)) {
                yield item; // Filtered items still tainted
            }
        }
    }

    async *mapGenerator(source, mapper) {
        for await (const item of source) {
            yield mapper(item); // Mapped items still tainted
        }
    }

    async composedGeneratorVulnerability(taintedItems) {
        // Chain: source -> filter -> map -> sink
        const source = this.taintedGenerator(taintedItems);
        const filtered = this.filterGenerator(source, x => x.length > 2);
        const mapped = this.mapGenerator(filtered, x => x.trim());

        for await (const value of mapped) {
            // TAINT SINK: Composed generator output is tainted
            fs.readFileSync(value); // VULNERABILITY: Path Traversal
        }
    }

    /**
     * VULNERABILITY: Async generator with yield*
     */
    async *delegatingGenerator(items1, items2) {
        yield* this.taintedGenerator(items1); // Delegates tainted values
        yield* this.taintedGenerator(items2); // More tainted values
    }

    async useDelegatingGenerator(items1, items2) {
        for await (const value of this.delegatingGenerator(items1, items2)) {
            // TAINT SINK: Both delegated sources are tainted
            exec(value); // VULNERABILITY
        }
    }
}

// =============================================================================
// STREAM PIPELINE TAINT TESTS
// =============================================================================

class StreamPipelineTaintTests {
    /**
     * VULNERABILITY: Readable stream with tainted data
     */
    createTaintedReadable(taintedItems) {
        let index = 0;
        return new Readable({
            objectMode: true,
            read() {
                if (index < taintedItems.length) {
                    this.push(taintedItems[index++]); // TAINTED chunks
                } else {
                    this.push(null);
                }
            }
        });
    }

    /**
     * VULNERABILITY: Transform stream preserves taint
     */
    createTransformStream() {
        return new Transform({
            objectMode: true,
            transform(chunk, encoding, callback) {
                // Transform doesn't sanitize
                callback(null, chunk.toString().toUpperCase()); // STILL TAINTED
            }
        });
    }

    /**
     * VULNERABILITY: Writable stream sink
     */
    createVulnerableWritable() {
        return new Writable({
            objectMode: true,
            write(chunk, encoding, callback) {
                // TAINT SINK: Command Injection
                exec(`echo ${chunk}`, callback); // VULNERABILITY
            }
        });
    }

    /**
     * VULNERABILITY: Pipeline with taint flow
     */
    pipelineTaintFlow(taintedItems) {
        const readable = this.createTaintedReadable(taintedItems);
        const transform = this.createTransformStream();
        const writable = this.createVulnerableWritable();

        pipeline(readable, transform, writable, (err) => {
            if (err) console.error('Pipeline error:', err);
        }); // Entire pipeline propagates taint
    }

    /**
     * VULNERABILITY: Promisified pipeline
     */
    async asyncPipelineTaint(taintedItems) {
        const pipelineAsync = promisify(pipeline);
        const readable = this.createTaintedReadable(taintedItems);

        const chunks = [];
        const collector = new Writable({
            objectMode: true,
            write(chunk, enc, cb) {
                chunks.push(chunk);
                cb();
            }
        });

        await pipelineAsync(readable, this.createTransformStream(), collector);

        // TAINT SINK: Collected chunks are tainted
        chunks.forEach(c => {
            const query = `INSERT INTO log VALUES ('${c}')`;
            console.log(query); // VULNERABILITY
        });
    }
}

// =============================================================================
// OBSERVABLE PATTERN TAINT TESTS
// =============================================================================

class ObservablePatternTaintTests {
    /**
     * Simple Observable implementation for testing
     */
    createObservable(producer) {
        return {
            subscribe: (observer) => {
                producer({
                    next: (value) => observer.next?.(value),
                    error: (err) => observer.error?.(err),
                    complete: () => observer.complete?.()
                });
            }
        };
    }

    /**
     * VULNERABILITY: Observable with tainted source
     */
    taintedObservable(taintedItems) {
        return this.createObservable((observer) => {
            taintedItems.forEach((item, i) => {
                setTimeout(() => {
                    observer.next(item); // TAINTED emissions
                    if (i === taintedItems.length - 1) {
                        observer.complete();
                    }
                }, i * 10);
            });
        });
    }

    /**
     * VULNERABILITY: Observable map preserves taint
     */
    mapObservable(source, mapper) {
        return this.createObservable((observer) => {
            source.subscribe({
                next: (value) => observer.next(mapper(value)), // TAINTED
                error: (err) => observer.error(err),
                complete: () => observer.complete()
            });
        });
    }

    /**
     * VULNERABILITY: Observable subscribe sink
     */
    subscribeWithVulnerableSink(taintedItems) {
        const source = this.taintedObservable(taintedItems);
        const mapped = this.mapObservable(source, x => x.toUpperCase());

        mapped.subscribe({
            next: (value) => {
                // TAINT SINK: Observable emission is tainted
                exec(`process ${value}`); // VULNERABILITY
            },
            error: (err) => console.error(err),
            complete: () => console.log('done')
        });
    }

    /**
     * VULNERABILITY: Observable filter still tainted
     */
    filterObservable(source, predicate) {
        return this.createObservable((observer) => {
            source.subscribe({
                next: (value) => {
                    if (predicate(value)) {
                        observer.next(value); // Filtered but STILL TAINTED
                    }
                },
                error: (err) => observer.error(err),
                complete: () => observer.complete()
            });
        });
    }

    filteredObservableVulnerability(taintedItems) {
        const source = this.taintedObservable(taintedItems);
        const filtered = this.filterObservable(source, x => x.length > 3);

        filtered.subscribe({
            next: (value) => {
                // TAINT SINK: Filtered values are tainted
                fs.writeFileSync(value, 'data'); // VULNERABILITY
            }
        });
    }
}

// =============================================================================
// EVENT EMITTER ASYNC TAINT TESTS
// =============================================================================

class EventEmitterAsyncTaintTests {
    /**
     * VULNERABILITY: Async event handler receives taint
     */
    asyncEventHandlerTaint(userInput) {
        const emitter = new EventEmitter();

        // Async handler
        emitter.on('data', async (data) => {
            const processed = await Promise.resolve(data.toUpperCase());
            // TAINT SINK: Async processed data is tainted
            exec(processed); // VULNERABILITY
        });

        // TAINT SOURCE
        emitter.emit('data', userInput);
    }

    /**
     * VULNERABILITY: events.once with async
     */
    async eventsOnceTaint(userInput) {
        const { once } = require('events');
        const emitter = new EventEmitter();

        setTimeout(() => emitter.emit('data', userInput), 10);

        // TAINT SOURCE via once()
        const [data] = await once(emitter, 'data');

        // TAINT SINK
        const query = `SELECT * FROM t WHERE x = '${data}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: EventEmitter as async iterator
     */
    async eventAsAsyncIterator(inputs) {
        const { on } = require('events');
        const emitter = new EventEmitter();

        // Emit tainted values
        setTimeout(() => {
            inputs.forEach((input, i) => {
                setTimeout(() => emitter.emit('data', input), i * 10);
            });
            setTimeout(() => emitter.emit('end'), inputs.length * 10 + 100);
        }, 0);

        // Async iteration over events
        const ac = new AbortController();
        setTimeout(() => ac.abort(), inputs.length * 10 + 200);

        try {
            for await (const [data] of on(emitter, 'data', { signal: ac.signal })) {
                // TAINT SINK: Each event data is tainted
                exec(`process ${data}`); // VULNERABILITY
            }
        } catch (err) {
            // AbortError expected
        }
    }
}

// =============================================================================
// CALLBACK TO PROMISE CONVERSION TAINT TESTS
// =============================================================================

class CallbackPromiseConversionTaintTests {
    /**
     * VULNERABILITY: Promisified callback preserves taint
     */
    async promisifyCallbackTaint(userInput) {
        const callbackFn = (data, callback) => {
            setTimeout(() => callback(null, data.toUpperCase()), 10);
        };

        const promisified = promisify(callbackFn);

        // TAINT SOURCE -> promisified function
        const result = await promisified(userInput);

        // TAINT SINK
        exec(result); // VULNERABILITY
    }

    /**
     * VULNERABILITY: util.callbackify preserves taint
     */
    callbackifyTaint(userInput) {
        const { callbackify } = require('util');

        const asyncFn = async (data) => {
            await new Promise(r => setTimeout(r, 10));
            return data.toLowerCase(); // STILL TAINTED
        };

        const callbackified = callbackify(asyncFn);

        callbackified(userInput, (err, result) => {
            if (!err) {
                // TAINT SINK
                fs.readFileSync(result); // VULNERABILITY
            }
        });
    }

    /**
     * VULNERABILITY: Manual callback-to-promise conversion
     */
    manualPromiseWrap(userInput) {
        return new Promise((resolve, reject) => {
            // Simulated async callback
            setTimeout(() => {
                resolve(userInput.trim()); // TAINTED value in promise
            }, 10);
        }).then(result => {
            // TAINT SINK
            const query = `INSERT INTO t VALUES ('${result}')`;
            console.log(query); // VULNERABILITY
        });
    }
}

// =============================================================================
// MICROTASK/MACROTASK TAINT TESTS
// =============================================================================

class MicrotaskMacrotaskTaintTests {
    /**
     * VULNERABILITY: queueMicrotask preserves taint
     */
    microtaskTaint(userInput) {
        // TAINT SOURCE captured
        queueMicrotask(() => {
            // TAINT SINK: Microtask has tainted closure
            exec(userInput); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: process.nextTick preserves taint
     */
    nextTickTaint(userInput) {
        // TAINT SOURCE captured
        process.nextTick(() => {
            // TAINT SINK: nextTick has tainted closure
            fs.writeFileSync(userInput, 'data'); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: setImmediate preserves taint
     */
    setImmediateTaint(userInput) {
        // TAINT SOURCE captured
        setImmediate(() => {
            // TAINT SINK
            const query = `SELECT * FROM t WHERE x = '${userInput}'`;
            console.log(query); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: Mixed micro/macro task chain
     */
    mixedTaskChainTaint(userInput) {
        let tainted = userInput;

        // Microtask
        queueMicrotask(() => {
            tainted = tainted.toUpperCase();

            // Macrotask
            setTimeout(() => {
                tainted = tainted.trim();

                // Microtask
                Promise.resolve().then(() => {
                    // TAINT SINK: After mixed task chain
                    exec(tainted); // VULNERABILITY
                });
            }, 0);
        });
    }
}

// =============================================================================
// TEST RUNNER
// =============================================================================

function runAdvancedAsyncPatternTests() {
    console.log('='.repeat(60));
    console.log('ADVANCED ASYNC PATTERN TAINT TEST SUITE');
    console.log('='.repeat(60));
    console.log('');
    console.log('Test Categories:');
    console.log('  1. Promise Chains (7 tests)');
    console.log('  2. Async/Await (7 tests)');
    console.log('  3. Async Generators (5 tests)');
    console.log('  4. Stream Pipelines (4 tests)');
    console.log('  5. Observable Patterns (4 tests)');
    console.log('  6. EventEmitter Async (3 tests)');
    console.log('  7. Callback/Promise Conversion (3 tests)');
    console.log('  8. Microtask/Macrotask (4 tests)');
    console.log('');
    console.log('Expected Vulnerabilities: 50+');
    console.log('='.repeat(60));
}

module.exports = {
    PromiseChainTaintTests,
    AsyncAwaitTaintTests,
    AsyncGeneratorTaintTests,
    StreamPipelineTaintTests,
    ObservablePatternTaintTests,
    EventEmitterAsyncTaintTests,
    CallbackPromiseConversionTaintTests,
    MicrotaskMacrotaskTaintTests,
    runAdvancedAsyncPatternTests
};
