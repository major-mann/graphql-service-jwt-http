module.exports = createContextCreator

function createContextCreator({ resolver,
                                verifyRequestToken,
                                generateToken,
                                laxTokenHeader,
                                queryTokenName = 'token',
                                bodyTokenName = 'token',
                                authorizationHeaderName = 'authorization',
                                tokenTypeName = 'bearer',
                                createLogger = defaultCreateLogger,
                                createStat = defaultCreateStat,
                                INTERNAL_USER,
                                INTERNAL_ISSUER
}) {
    return function createContext({ req }) {
        const issuer = determineIssuer(req);
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
            resolve: resolver,
            isInternalUser: sub => sub === INTERNAL_USER,
            isInternalIssuer: iss => iss === INTERNAL_ISSUER,
            token: {
                generate: (claims, options) => generateToken(issuer, claims, options),
                verify: token => verifyRequestToken(token, context)
            }
        };
        return context;

        async function verifyToken(source, token) {
            try {
                const claims = await verifyRequestToken(token, context);
                return claims;
            } catch (ex) {
                log.debug(`Invalid token "${req.body[bodyTokenName]}" received in ${source}. ${ex.stack}`);
                return false;
            }
        }
    };

    function extractBearer(authorization) {
        if (typeof authorization !== 'string') {
            return undefined;
        }
        const [type, token] = authorization.split(' ');
        if (laxTokenHeader) {
            return token || type;
        } else if (type.toLowerCase() === tokenTypeName) {
            return token;
        } else {
            return undefined;
        }
    }
}

function determineIssuer(request) {
    // TODO: Check this is correct and works as expected
    // TODO: What about port?
    const issuer = `${request.protocol}://${request.hostname}`;
    return issuer;
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
