module.exports = createContextCreator;

const uuid = require(`uuid`);

function createContextCreator({ verifyRequestToken,
                                generateToken,
                                laxTokenHeader,
                                queryTokenName = `token`,
                                bodyTokenName = `token`,
                                authorizationHeaderName = `authorization`,
                                tokenTypeName = `bearer`,
                                createLogger = defaultCreateLogger,
                                createStat = defaultCreateStat
}) {
    return async function createContext({ req }) {
        const checks = {
            body: bodyTokenName && req.body && req.body[bodyTokenName],
            query: queryTokenName && req.query && req.query[queryTokenName],
            [`authorization header (${authorizationHeaderName})`]: authorizationHeaderName &&
                req.headers[authorizationHeaderName] &&
                extractBearer(req.headers[authorizationHeaderName])
        };

        let user;
        for (const [source, token] of Object.entries(checks)) {
            if (!token) {
                continue;
            }
            user = await verifyToken(source, token);
            if (user) {
                break;
            }
        }

        const log = createLogger(req, user);
        const stat = createStat(req, user);
        const context = {
            log,
            stat,
            user,
            token: {
                generate: (claims, options, params) => generateToken(claims, options, params),
                verify: (token, params) => verifyRequestToken(token, params)
            }
        };

        return context;

        async function verifyToken(source, token, params) {
            try {
                const claims = await verifyRequestToken(token, params);
                return claims;
            } catch (ex) {
                switch (ex.name) {
                    case `JsonWebTokenError`:
                        throw new Error(`Token error: ${ex.message}`);
                    case `TokenExpiredError`:
                        throw new Error(`Token expired at ${ex.expiredAt.toISOString()}`);
                    default: {
                        const id = uuid.v4().replace(/-/g, ``);
                        createLogger(req).warn(`Unable to validate token "${token}" received in ${source}. ${id} ` +
                            `${ex.name} ${ex.stack}`);
                        throw new Error(`Internal server error. Please send "${id}" to support to assist with ` +
                            `identifying error`);
                    }
                }
            }
        }
    };

    function extractBearer(authorization) {
        if (typeof authorization !== `string`) {
            return undefined;
        }
        const [type, token] = authorization.split(` `);
        if (laxTokenHeader) {
            return token || type;
        } else if (type.toLowerCase() === tokenTypeName) {
            return token;
        } else {
            return undefined;
        }
    }
}

function defaultCreateLogger() {
    return console;
}

function defaultCreateStat() {
    // This is just a placeholder so a stats client can be passed in
    return {
        increment: () => undefined,
        decrement: () => undefined,
        counter: () => undefined,
        gauge: () => undefined,
        gaugeDelta: () => undefined,
        set: () => undefined,
        histogram: () => undefined,
    };
}
