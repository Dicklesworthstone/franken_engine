// Real-world program #2: JSON API Server Handler
// Features: ES2015 classes, destructuring, arrow functions, Map, JSON operations, regex

class APIRequest {
    constructor(method, path, headers = {}, body = '') {
        this.method = method.toUpperCase();
        this.path = path;
        this.headers = headers;
        this.body = body;
        this.timestamp = Date.now();
    }

    getContentType() {
        return this.headers['content-type'] || this.headers['Content-Type'] || '';
    }

    isJSON() {
        return this.getContentType().includes('application/json');
    }

    parseBody() {
        if (!this.body || !this.isJSON()) {
            return null;
        }

        try {
            return JSON.parse(this.body);
        } catch (error) {
            throw new Error('Invalid JSON body: ' + error.message);
        }
    }
}

class APIResponse {
    constructor(status = 200, data = null, headers = {}) {
        this.status = status;
        this.data = data;
        this.headers = {
            'Content-Type': 'application/json',
            'X-Powered-By': 'FrankenEngine',
            ...headers
        };
        this.timestamp = Date.now();
    }

    toJSON() {
        return JSON.stringify({
            status: this.status,
            data: this.data,
            headers: this.headers,
            timestamp: this.timestamp
        });
    }
}

class RouteHandler {
    constructor() {
        this.routes = new Map();
        this.middleware = [];
    }

    // Add middleware function
    use(fn) {
        this.middleware.push(fn);
        return this;
    }

    // Register route handler
    addRoute(method, pattern, handler) {
        const key = `${method.toUpperCase()}:${pattern}`;
        this.routes.set(key, { pattern, handler, method: method.toUpperCase() });
        return this;
    }

    // Convenience methods
    get(pattern, handler) { return this.addRoute('GET', pattern, handler); }
    post(pattern, handler) { return this.addRoute('POST', pattern, handler); }
    put(pattern, handler) { return this.addRoute('PUT', pattern, handler); }
    delete(pattern, handler) { return this.addRoute('DELETE', pattern, handler); }

    // Parse path parameters
    parsePathParams(pattern, path) {
        const params = {};
        const patternRegex = pattern.replace(/:([^/]+)/g, '([^/]+)');
        const fullRegex = new RegExp('^' + patternRegex + '$');

        const match = path.match(fullRegex);
        if (!match) return null;

        const paramNames = pattern.match(/:([^/]+)/g);
        if (paramNames) {
            paramNames.forEach((paramName, index) => {
                const key = paramName.substring(1); // remove ':'
                params[key] = match[index + 1];
            });
        }

        return params;
    }

    // Find matching route
    findRoute(method, path) {
        for (const [key, route] of this.routes) {
            if (route.method !== method.toUpperCase()) continue;

            // Exact match
            if (route.pattern === path) {
                return { route, params: {} };
            }

            // Parameter match
            const params = this.parsePathParams(route.pattern, path);
            if (params !== null) {
                return { route, params };
            }
        }
        return null;
    }

    // Execute middleware chain
    async executeMiddleware(request, response) {
        for (const middleware of this.middleware) {
            try {
                await middleware(request, response);
            } catch (error) {
                throw new Error('Middleware error: ' + error.message);
            }
        }
    }

    // Handle request
    async handleRequest(request) {
        try {
            const response = new APIResponse();

            // Execute middleware
            await this.executeMiddleware(request, response);

            // Find route
            const match = this.findRoute(request.method, request.path);

            if (!match) {
                return new APIResponse(404, {
                    error: 'Route not found',
                    path: request.path,
                    method: request.method
                });
            }

            // Execute route handler
            request.params = match.params;
            const result = await match.route.handler(request, response);

            if (result instanceof APIResponse) {
                return result;
            } else {
                response.data = result;
                return response;
            }

        } catch (error) {
            return new APIResponse(500, {
                error: 'Internal server error',
                message: error.message
            });
        }
    }
}

// Create API server
function createAPIServer() {
    const server = new RouteHandler();

    // Add logging middleware
    server.use((request, response) => {
        console.log(`${request.method} ${request.path} at ${new Date().toISOString()}`);
        return Promise.resolve();
    });

    // Add validation middleware
    server.use((request, response) => {
        if (request.method === 'POST' || request.method === 'PUT') {
            if (!request.isJSON()) {
                throw new Error('Content-Type must be application/json');
            }
        }
        return Promise.resolve();
    });

    // Routes
    server.get('/health', (req, res) => {
        return { status: 'healthy', timestamp: Date.now() };
    });

    server.get('/users/:id', (req, res) => {
        const { id } = req.params;
        return {
            user: {
                id: parseInt(id),
                name: `User ${id}`,
                email: `user${id}@example.com`
            }
        };
    });

    server.post('/users', (req, res) => {
        const userData = req.parseBody();

        if (!userData.name || !userData.email) {
            return new APIResponse(400, {
                error: 'Missing required fields',
                required: ['name', 'email']
            });
        }

        return new APIResponse(201, {
            user: {
                id: Math.floor(Math.random() * 1000),
                name: userData.name,
                email: userData.email,
                created: new Date().toISOString()
            }
        });
    });

    server.get('/api/stats', (req, res) => {
        return {
            routes: server.routes.size,
            middleware: server.middleware.length,
            uptime: Date.now()
        };
    });

    return server;
}

// Test the API server
async function testAPIServer() {
    console.log('Testing JSON API Server Handler...');

    const server = createAPIServer();

    // Test cases
    const testCases = [
        new APIRequest('GET', '/health'),
        new APIRequest('GET', '/users/123'),
        new APIRequest('GET', '/api/stats'),
        new APIRequest('POST', '/users', {
            'Content-Type': 'application/json'
        }, JSON.stringify({ name: 'Alice', email: 'alice@example.com' })),
        new APIRequest('POST', '/users', {
            'Content-Type': 'application/json'
        }, JSON.stringify({ name: 'Bob' })), // Missing email
        new APIRequest('GET', '/nonexistent'),
        new APIRequest('POST', '/users', {}, 'invalid body'), // No content-type
    ];

    const results = [];

    for (const [index, request] of testCases.entries()) {
        console.log(`\nTest ${index + 1}: ${request.method} ${request.path}`);

        const response = await server.handleRequest(request);
        console.log(`Response: ${response.status} - ${response.toJSON()}`);

        results.push({
            request: {
                method: request.method,
                path: request.path,
                hasBody: !!request.body
            },
            response: {
                status: response.status,
                hasData: !!response.data
            }
        });
    }

    return {
        testsRun: testCases.length,
        results,
        serverStats: {
            routes: server.routes.size,
            middleware: server.middleware.length
        }
    };
}

// Execute test
testAPIServer().then(result => {
    console.log('\nFinal result:', JSON.stringify(result));
}).catch(error => {
    console.error('Test failed:', error.message);
});

// Export for module testing
if (typeof module !== 'undefined') {
    module.exports = { APIRequest, APIResponse, RouteHandler, createAPIServer };
}