module.exports = {
    validator: createValidator,
    generator: createGenerator
};

const SERVICE_KEY_FIELDS = `
    iss
    kty
    use
    key_ops
    alg
    kid
    x5u
    x5c
    x5t
    x5t_S256
    e
    d
    k
    n
    p
    q
    x
    y
    dp
    dq
    qi
    crv
`;

const THROTTLE_PARAMS = [`type`, `kid`, `iss`, `aud`];

const { graphql } = require(`graphql`);
const jwt = require(`jsonwebtoken`);
const jwkToPem = require(`jwk-to-pem`);
const throttle = require(`lodash.throttle`);

const gql = (strings, ...params) => strings.map((str, idx) => `${str}${params[idx] || ``}`).join(``);

function createValidator({ schema,
                           createContext,
                           loadIssuerData,
                           keyFetchThrottleTime = 0 }) {
    const searcher = {};
    return validator;

    async function validator(token, params) {
        const decoded = jwt.decode(token, { complete: true });
        params = params || {
            source: {},
            context: createContext()
        };

        let key = await keySearch(`accepted`);
        if (!key) {
            key = await keySearch(`issued`);
        }
        if (!key) {
            throw new Error(`key not found in accepted or issued schemas (iss: "${decoded.payload.iss}", ` +
                `kid: "${decoded.header.kid || decoded.payload.kid}", aud: ${decoded.payload.aud})`);
        }

        const info = await issuerData();
        if (!info) {
            throw new Error(`No issuer data for issuer "${decoded.payload.iss}" could be found!`);
        }

        let claims = await verify(token, key.key, info.options);
        if (typeof info.mask === `function`) {
            claims = await info.mask(claims);
        } else if (Array.isArray(info.mask)) {
            claims = info.mask.reduce((result, name) => {
                result[name] = claims[name];
                return result;
            }, {});
        }
        if (info.claims) {
            claims = {
                claims,
                ...info.claims
            };
        }
        return claims;

        async function keySearch(type) {
            const keySearcher = getKeySearcher({
                type,
                kid: decoded.header.kid || decoded.payload.kid,
                iss: decoded.payload.iss,
                aud: decoded.payload.aud
            });
            const key = await keySearcher(
                params,
                type,
                decoded.header.kid || decoded.payload.kid,
                decoded.payload.iss,
                decoded.payload.aud
            );
            return key;
        }

        async function issuerData() {
            if (typeof loadIssuerData === `function`) {
                const data = await loadIssuerData(decoded.payload.iss);
                return data;
            } else {
                return undefined;
            }
        }
    }

    async function findVerificationKey(params, type, kid, iss, aud) {
        // TODO: Can we compile the query the first time or something?
        const result = await exec(schema, gql`
            query FindVerificationKey($kid: String!, $iss: String!, $aud: String!) {
                serviceKey {
                    ${type} {
                        find(kid: $kid, iss: $iss, aud: $aud) {
                            ${SERVICE_KEY_FIELDS}
                        }
                    }
                }
            }
        `, params.source, params.context, { kid, iss, aud });
        let key = result.serviceKey[type].find;
        if (key) {
            return {
                kid: key.kid,
                key: jwkToPem(key)
            };
        }
        return key;
    }

    function getKeySearcher(args) {
        const cacheName = THROTTLE_PARAMS
            .map(param => args[param])
            .join(`:::`);
        if (!searcher[cacheName]) {
            searcher[cacheName] = throttle(findVerificationKey, keyFetchThrottleTime);
        }
        return searcher[cacheName];
    }
}

function createGenerator({ schema, createContext, keyFetchThrottleTime = 0 }) {
    const searcher = {};
    return generate;

    async function generate(claims, options, params) {
        params = params || {
            source: {},
            context: createContext()
        };
        const keySearcher = getKeySearcher(claims.aud);
        const key = await keySearcher(claims.aud, params);

        const now = Math.floor(Date.now() / 1000);
        claims = {
            ...claims,
            iat: now
        };

        options = options || {};
        options.header = options.header || {};
        const tokenData = await sign(claims, key.key, {
            ...options,
            header: {
                kid: key.kid,
                ...options.header
            }
        });
        return tokenData;
    }

    function getKeySearcher(aud) {
        if (!searcher[aud]) {
            searcher[aud] = throttle(getLatestKey, keyFetchThrottleTime);
        }
        return searcher[aud];
    }

    async function getLatestKey(aud, params) {
        const filter = { field: `aud`, op: `EQ`, value: aud };
        const result = await exec(schema, gql`
            query FindLatestVerificationKey($filter: DataSourceFilterInput!) {
                serviceKey {
                    issued {
                        list(first: 1, order: [{ field: "created", desc: true }], filter: [$filter]) {
                            edges {
                                node {
                                    ${SERVICE_KEY_FIELDS}
                                }
                            }
                        }
                    }
                }
            }
        `, params.source, params.context, { filter });
        const latest = result.serviceKey.issued.list.edges[0];
        if (latest) {
            return {
                kid: latest.node.kid,
                key: jwkToPem(latest.node, { private: true })
            };
        } else {
            return undefined;
        }
    }
}

function sign(claims, key, options) {
    return new Promise(function promiseHandler(resolve, reject) {
        jwt.sign(claims, key, options, function onSigned(err, tokenData) {
            if (err) {
                reject(err);
            } else {
                resolve(tokenData);
            }
        });
    });
}

function verify(token, key, options) {
    return new Promise(function promiseHandler(resolve, reject) {
        jwt.verify(token, key, options, function onVerified(err, decoded) {
            if (err) {
                reject(err);
            } else {
                resolve(decoded);
            }
        });
    });
}

async function exec(schema, query, source, context, variables) {
    const result = await graphql(schema, query, source, context, variables);
    if (result.errors && result.errors.length) {
        if (result.errors.length === 1 && result.errors[0] instanceof Error) {
            throw result.errors[0];
        }
        throw new Error(result.errors.map(error => error.message || error).join(`\n`));
    }
    return result.data;
}
