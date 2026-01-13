/**
 * =============================================================================
 * EXPRESS.JS MIDDLEWARE TAINT ANALYSIS TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation through Express.js middleware chains,
 * route handlers, and common patterns in Node.js web applications.
 *
 * CRITICAL SCENARIOS:
 * 1. Request object taint (params, query, body, headers, cookies)
 * 2. Middleware chain taint propagation
 * 3. Response injection vulnerabilities
 * 4. Route parameter injection
 * 5. Error handling taint leakage
 *
 * =============================================================================
 */

const express = require('express');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// =============================================================================
// REQUEST OBJECT TAINT TESTS
// =============================================================================

class ExpressRequestTaintTests {
    /**
     * VULNERABILITY: req.params are tainted
     */
    routeParamsTaint(req, res) {
        // TAINT SOURCE: Route parameters
        const userId = req.params.userId;
        const fileId = req.params.fileId;

        // TAINT SINK: SQL Injection via route param
        const query = `SELECT * FROM users WHERE id = '${userId}'`;
        console.log(query); // VULNERABILITY

        // TAINT SINK: Path Traversal via route param
        const filePath = path.join('/uploads', fileId);
        fs.readFileSync(filePath); // VULNERABILITY
    }

    /**
     * VULNERABILITY: req.query are tainted
     */
    queryParamsTaint(req, res) {
        // TAINT SOURCE: Query parameters (?search=xxx&sort=yyy)
        const search = req.query.search;
        const sortBy = req.query.sort;
        const limit = req.query.limit;

        // TAINT SINK: SQL Injection via query params
        const query = `SELECT * FROM products WHERE name LIKE '%${search}%' ORDER BY ${sortBy} LIMIT ${limit}`;
        console.log(query); // VULNERABILITY (multiple injection points)
    }

    /**
     * VULNERABILITY: req.body is tainted
     */
    requestBodyTaint(req, res) {
        // TAINT SOURCE: Request body (JSON, form data)
        const { username, email, query: userQuery } = req.body;

        // TAINT SINK: SQL Injection
        const sql = `INSERT INTO users (username, email) VALUES ('${username}', '${email}')`;
        console.log(sql); // VULNERABILITY

        // TAINT SINK: Command Injection
        exec(`echo "${userQuery}" | grep pattern`, (err, stdout) => {
            res.send(stdout);
        }); // VULNERABILITY
    }

    /**
     * VULNERABILITY: req.headers are tainted
     */
    headersTaint(req, res) {
        // TAINT SOURCE: HTTP headers
        const userAgent = req.headers['user-agent'];
        const customHeader = req.headers['x-custom-data'];
        const referer = req.headers['referer'];

        // TAINT SINK: Log Injection
        console.log(`User-Agent: ${userAgent}`); // VULNERABILITY
        console.log(`Referer: ${referer}`); // VULNERABILITY

        // TAINT SINK: Header Injection in response
        res.setHeader('X-Custom-Response', customHeader); // VULNERABILITY
    }

    /**
     * VULNERABILITY: req.cookies are tainted
     */
    cookiesTaint(req, res) {
        // TAINT SOURCE: Cookies
        const sessionId = req.cookies.sessionId;
        const preferences = req.cookies.preferences;

        // TAINT SINK: SQL Injection via cookie
        const query = `SELECT * FROM sessions WHERE id = '${sessionId}'`;
        console.log(query); // VULNERABILITY

        // TAINT SINK: Code Injection (if preferences is JSON parsed unsafely)
        const prefs = JSON.parse(preferences);
        eval(prefs.callback); // VULNERABILITY
    }

    /**
     * VULNERABILITY: req.hostname/ip can be spoofed
     */
    hostInfoTaint(req, res) {
        // TAINT SOURCE: These can be spoofed via headers
        const hostname = req.hostname; // From Host header
        const ip = req.ip; // From X-Forwarded-For
        const protocol = req.protocol;

        // TAINT SINK: SSRF via hostname
        const apiUrl = `${protocol}://${hostname}/internal-api`;
        fetch(apiUrl); // VULNERABILITY: SSRF

        // TAINT SINK: Log Injection
        console.log(`Request from ${ip}`); // VULNERABILITY
    }
}

// =============================================================================
// MIDDLEWARE CHAIN TAINT TESTS
// =============================================================================

class MiddlewareChainTaintTests {
    /**
     * VULNERABILITY: Taint persists through middleware chain
     */
    setupMiddlewareChain(app) {
        // Middleware 1: "Validation" that doesn't sanitize
        app.use((req, res, next) => {
            // This looks like validation but DOES NOT sanitize
            if (req.body && req.body.username) {
                req.body.username = req.body.username.trim();
            }
            req.validated = true; // False sense of security
            next();
        });

        // Middleware 2: "Transformation" that preserves taint
        app.use((req, res, next) => {
            if (req.body) {
                req.transformedBody = {
                    ...req.body,
                    processedAt: Date.now()
                };
            }
            next();
        });

        // Final handler - data is STILL tainted
        app.post('/api/user', (req, res) => {
            // Developer thinks data is validated
            const username = req.transformedBody.username; // STILL TAINTED

            // TAINT SINK: SQL Injection
            const query = `INSERT INTO users (name) VALUES ('${username}')`;
            console.log(query); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: res.locals spreads taint
     */
    resLocalsTaint(app) {
        // Middleware stores tainted data in res.locals
        app.use((req, res, next) => {
            // TAINT SOURCE
            res.locals.userInput = req.query.input;
            res.locals.userId = req.params.id;
            next();
        });

        // Route handler uses res.locals
        app.get('/api/data/:id', (req, res) => {
            // res.locals values are still tainted
            const input = res.locals.userInput;

            // TAINT SINK: Command Injection
            execSync(`process ${input}`); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: Custom request properties preserve taint
     */
    customRequestPropertyTaint(app) {
        // Auth middleware adds user from token
        app.use((req, res, next) => {
            const authHeader = req.headers.authorization; // TAINTED
            // Simulated token decode (in reality would use JWT)
            req.user = {
                id: authHeader.split('.')[1], // TAINTED
                role: req.headers['x-user-role'] // TAINTED
            };
            next();
        });

        app.get('/admin', (req, res) => {
            // req.user properties are tainted
            const userId = req.user.id;

            // TAINT SINK: SQL Injection
            const query = `SELECT * FROM admin WHERE user_id = '${userId}'`;
            console.log(query); // VULNERABILITY
        });
    }

    /**
     * VULNERABILITY: Error middleware leaks tainted data
     */
    errorMiddlewareLeak(app) {
        // Error handler that leaks tainted data
        app.use((err, req, res, next) => {
            // TAINT SOURCE: Error might contain user input
            const errorMessage = err.message;

            // TAINT SINK: XSS via error response
            res.status(500).send(`
                <html>
                    <body>
                        <h1>Error</h1>
                        <p>${errorMessage}</p>
                        <p>Query: ${req.query.q}</p>
                    </body>
                </html>
            `); // VULNERABILITY: Reflected XSS
        });
    }
}

// =============================================================================
// RESPONSE INJECTION TESTS
// =============================================================================

class ResponseInjectionTests {
    /**
     * VULNERABILITY: res.send with tainted data
     */
    resSendXss(req, res) {
        // TAINT SOURCE
        const name = req.query.name;

        // TAINT SINK: XSS via res.send
        res.send(`<h1>Hello, ${name}!</h1>`); // VULNERABILITY
    }

    /**
     * VULNERABILITY: res.render with tainted locals
     */
    resRenderXss(req, res) {
        // TAINT SOURCE
        const title = req.body.title;
        const content = req.body.content;

        // TAINT SINK: XSS via template rendering
        // (depends on template engine's auto-escaping)
        res.render('page', {
            title: title, // VULNERABILITY (if not auto-escaped)
            content: content,
            unsafeContent: req.body.html // Explicit unsafe
        });
    }

    /**
     * VULNERABILITY: res.json can enable XSS in certain contexts
     */
    resJsonXss(req, res) {
        // TAINT SOURCE
        const userData = req.body;

        // If this JSON is embedded in HTML without proper escaping
        // it can lead to XSS via </script> injection
        res.json({
            message: userData.message, // Could contain </script><script>evil</script>
            callback: userData.callback
        }); // POTENTIAL VULNERABILITY
    }

    /**
     * VULNERABILITY: res.redirect with tainted URL
     */
    resRedirectOpenRedirect(req, res) {
        // TAINT SOURCE
        const returnUrl = req.query.returnUrl;
        const next = req.query.next;

        // TAINT SINK: Open Redirect
        res.redirect(returnUrl); // VULNERABILITY

        // Also vulnerable even with path check bypass
        if (next.startsWith('/')) {
            res.redirect(next); // VULNERABILITY: //evil.com is valid
        }
    }

    /**
     * VULNERABILITY: res.sendFile with tainted path
     */
    resSendFilePathTraversal(req, res) {
        // TAINT SOURCE
        const filename = req.params.filename;

        // TAINT SINK: Path Traversal
        res.sendFile(filename, { root: './uploads' }); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Header injection via res.set
     */
    resSetHeaderInjection(req, res) {
        // TAINT SOURCE
        const contentType = req.query.type;
        const customValue = req.headers['x-custom'];

        // TAINT SINK: Header Injection
        res.set('Content-Type', contentType); // VULNERABILITY
        res.set('X-Custom-Response', customValue); // VULNERABILITY

        // Could lead to response splitting if newlines not filtered
        res.send('data');
    }
}

// =============================================================================
// EXPRESS ROUTER TAINT TESTS
// =============================================================================

class ExpressRouterTaintTests {
    /**
     * VULNERABILITY: Router.param callback receives tainted value
     */
    routerParamTaint(router) {
        // param callback - id is TAINTED
        router.param('id', (req, res, next, id) => {
            // TAINT SINK: SQL Injection in param callback
            const query = `SELECT * FROM items WHERE id = '${id}'`;
            console.log(query); // VULNERABILITY

            req.item = { id: id }; // Storing tainted value
            next();
        });

        router.get('/item/:id', (req, res) => {
            // req.item.id is still tainted
            res.json(req.item);
        });
    }

    /**
     * VULNERABILITY: Nested routers preserve taint
     */
    nestedRouterTaint() {
        const mainRouter = express.Router();
        const userRouter = express.Router();

        userRouter.get('/:userId/profile', (req, res) => {
            // TAINT SOURCE: userId from nested route
            const userId = req.params.userId;

            // TAINT SINK: Path Traversal
            const profilePath = `/data/profiles/${userId}.json`;
            const profile = fs.readFileSync(profilePath); // VULNERABILITY

            res.json(JSON.parse(profile));
        });

        mainRouter.use('/users', userRouter);
        return mainRouter;
    }

    /**
     * VULNERABILITY: Express mounting preserves taint
     */
    mountedAppTaint() {
        const subApp = express();

        subApp.get('/data', (req, res) => {
            // req.query is still tainted even in mounted app
            const filter = req.query.filter;

            // TAINT SINK: Command Injection
            exec(`grep "${filter}" data.txt`, (err, stdout) => {
                res.send(stdout);
            }); // VULNERABILITY
        });

        return subApp;
    }
}

// =============================================================================
// EVENT EMITTER TAINT TESTS
// =============================================================================

class EventEmitterTaintTests {
    /**
     * VULNERABILITY: Taint through EventEmitter
     */
    eventEmitterTaint() {
        const EventEmitter = require('events');
        const emitter = new EventEmitter();

        // Handler receives tainted data
        emitter.on('userInput', (data) => {
            // TAINT SINK: SQL Injection via event data
            const query = `SELECT * FROM users WHERE name = '${data.name}'`;
            console.log(query); // VULNERABILITY

            // TAINT SINK: Command Injection via event data
            exec(data.command); // VULNERABILITY
        });

        // Event emitted with tainted data
        return (req, res) => {
            // TAINT SOURCE
            emitter.emit('userInput', {
                name: req.body.name,
                command: req.body.cmd
            });
            res.send('processed');
        };
    }

    /**
     * VULNERABILITY: Taint through 'once' listener
     */
    eventOnceListener() {
        const EventEmitter = require('events');
        const emitter = new EventEmitter();

        emitter.once('process', (filename) => {
            // TAINT SINK: Path Traversal
            fs.readFileSync(`/data/${filename}`); // VULNERABILITY
        });

        return (req, res) => {
            emitter.emit('process', req.params.file); // TAINTED
            res.send('ok');
        };
    }

    /**
     * VULNERABILITY: Taint through process events
     */
    processEventTaint() {
        // Warning: process events with tainted data
        return (req, res, next) => {
            const errorData = req.body.errorInfo; // TAINTED

            process.on('uncaughtException', (err) => {
                // TAINT SINK: Log Injection with original request data
                console.log(`Error with context: ${errorData}`); // VULNERABILITY
            });

            next();
        };
    }

    /**
     * VULNERABILITY: Readable stream 'data' event
     */
    streamDataEventTaint(req, res) {
        // Request body as stream - each chunk is tainted
        let body = '';

        req.on('data', (chunk) => {
            body += chunk; // Accumulating tainted data
        });

        req.on('end', () => {
            // TAINT SINK: Command Injection
            exec(`echo "${body}"`); // VULNERABILITY
        });
    }
}

// =============================================================================
// ASYNC/AWAIT EXPRESS PATTERN TESTS
// =============================================================================

class AsyncExpressTaintTests {
    /**
     * VULNERABILITY: Async handler preserves taint
     */
    async asyncHandlerTaint(req, res) {
        // TAINT SOURCE
        const userId = req.params.id;

        // Async operation doesn't remove taint
        const result = await new Promise((resolve) => {
            setTimeout(() => resolve(userId), 100);
        });

        // TAINT SINK: SQL Injection after async
        const query = `SELECT * FROM users WHERE id = '${result}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Promise chain preserves taint
     */
    promiseChainTaint(req, res) {
        // TAINT SOURCE
        const input = req.body.input;

        Promise.resolve(input)
            .then(val => val.toUpperCase())
            .then(val => val.trim())
            .then(val => {
                // TAINT SINK: Still tainted after chain
                exec(`process ${val}`); // VULNERABILITY
            });
    }

    /**
     * VULNERABILITY: Try/catch doesn't sanitize
     */
    async tryCatchTaint(req, res) {
        try {
            // TAINT SOURCE
            const data = req.body;

            // Some async operation
            await someAsyncOperation(data);

            // TAINT SINK: Even in try block
            const query = `INSERT INTO log VALUES ('${data.message}')`;
            console.log(query); // VULNERABILITY

        } catch (err) {
            // Error might contain tainted data
            res.status(500).send(`Error: ${err.message}`); // VULNERABILITY: XSS
        }
    }

    /**
     * VULNERABILITY: Express-async-errors pattern
     */
    asyncErrorHandlerTaint(req, res) {
        const asyncHandler = (fn) => (req, res, next) =>
            Promise.resolve(fn(req, res, next)).catch(next);

        return asyncHandler(async (req, res) => {
            // TAINT SOURCE
            const filename = req.query.file;

            // TAINT SINK: Path Traversal in async handler
            const content = await fs.promises.readFile(`/data/${filename}`); // VULNERABILITY

            res.send(content);
        });
    }
}

// =============================================================================
// TEST RUNNER
// =============================================================================

function runExpressMiddlewareTaintTests() {
    console.log('='.repeat(60));
    console.log('EXPRESS.JS MIDDLEWARE TAINT ANALYSIS TEST SUITE');
    console.log('='.repeat(60));
    console.log('');
    console.log('Test Categories:');
    console.log('  1. Request Object Taint (6 tests)');
    console.log('  2. Middleware Chain Taint (4 tests)');
    console.log('  3. Response Injection (6 tests)');
    console.log('  4. Express Router Taint (3 tests)');
    console.log('  5. EventEmitter Taint (4 tests)');
    console.log('  6. Async/Await Patterns (4 tests)');
    console.log('');
    console.log('Expected Vulnerabilities: 42');
    console.log('='.repeat(60));
}

// Helper function placeholder
async function someAsyncOperation(data) {
    return data;
}

module.exports = {
    ExpressRequestTaintTests,
    MiddlewareChainTaintTests,
    ResponseInjectionTests,
    ExpressRouterTaintTests,
    EventEmitterTaintTests,
    AsyncExpressTaintTests,
    runExpressMiddlewareTaintTests
};
