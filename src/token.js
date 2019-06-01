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

const { graphql } = require('graphql');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const throttle = require('lodash.throttle');

function createValidator({ schema,
                           createContext,
                           loadIssuerData,
                           keyFetchDebounceTime = 0 }) {

    const debouncedFindVerificationKey = throttle(findVerificationKey, keyFetchDebounceTime);
    return validator;

    async function validator(token) {
        const decoded = jwt.decode(token, { complete: true });

        let key = await debouncedFindVerificationKey('accepted', decoded.header.kid || decoded.payload.kid, decoded.payload.iss);
        if (!key) {
            key = await debouncedFindVerificationKey('issued', decoded.header.kid || decoded.payload.kid, decoded.payload.iss);
        }
        if (!key) {
            throw new Error('key not found in accepted or issued schemas')
        }

        const info = await issuerData();
        let claims = await verify(token, key.key, info && info.options);
        const mask = info && info.mask;
        if (typeof mask === 'function') {
            claims = await mask(claims);
        }
        if (info && info.claims) {
            claims = {
                claims,
                ...info.claims
            };
        }
        return claims;

        async function issuerData() {
            if (typeof loadIssuerData === 'function') {
                const data = await loadIssuerData(decoded.payload.iss);
                return data;
            } else {
                return undefined;
            }
        }
    };

    async function findVerificationKey(type, kid, iss) {
        // TODO: Can we compile the query the first time or something?
        const result = await exec(schema, `
            query FindVerificationKey($kid: String!, $iss: String!) {
                serviceKey {
                    ${type} {
                        find(kid: $kid, iss: $iss) {
                            ${SERVICE_KEY_FIELDS}
                        }
                    }
                }
            }
        `, createContext(), { kid, iss });
        let key = result.serviceKey[type].find;
        if (key) {
            key = jwkToPem(key);
            return {
                kid: latest.node.kid,
                key: jwkToPem(key)
            };
        }
        return key;
    }
}

function createGenerator({ schema, createContext, keyFetchDebounceTime = 0 }) {
    const debouncedGetLatestKey = throttle(getLatestKey, keyFetchDebounceTime);
    return generate;

    async function generate(claims, options) {
        const key = await debouncedGetLatestKey();

        const now = Math.floor(Date.now() / 1000);
        claims = {
            ...claims,
            iat: now
        };

        options = options || {};
        options.header = options.header || {};
        const tokenData = await sign(claims, key.key, {
            header: {
                kid: key.kid,
                ...options.header
            },
            ...options
        });
        return tokenData;
    };

    async function getLatestKey() {
        const result = await exec(schema, `
            query FindLatestVerificationKey {
                serviceKey {
                    issued {
                        list(first: 1, order: [{ field: "created", desc: true }]) {
                            edges {
                                node {
                                    ${SERVICE_KEY_FIELDS}
                                }
                            }
                        }
                    }
                }
            }
        `, createContext(), {});
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

async function exec(schema, query, context, variables) {
    const result = await graphql(schema, query, {}, context, variables);
    if (result.errors && result.errors.length) {
        throw new Error(results.errors.map(error => error.message || error).join('\n'));
    }
    return result.data;
}
