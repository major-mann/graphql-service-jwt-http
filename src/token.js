module.exports = {
    validator: createValidator,
    generator: createGenerator
};

const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const debounce = require('lodash.debounce');

function createValidator({ accepted,
                           issued,
                           resolver,
                           loadIssuerData,
                           debounceTime = 0,
                           acceptedTypeName = 'AcceptedServiceKeyQuery',
                           issuedTypeName = 'IssuedServiceKeyQuery' }) {

    const debouncedFindSigningKey = debounce(findSigningKey, debounceTime);
    const signingTypes = {
        issued: issued.getType(issuedTypeName),
        accepted: accepted.getType(acceptedTypeName)
    };

    return validator;

    async function validator(token) {
        const decoded = jwt.decode(token, { complete: true });

        let key;
        if (signingTypes.accepted) {
            key = await debouncedFindSigningKey('accepted', decoded.header.kid || decoded.payload.kid, decoded.payload.iss);
        }
        if (!key && issued) {
            key = await debouncedFindSigningKey('issued', decoded.header.kid || decoded.payload.kid, decoded.payload.iss);
        }
        if (!key) {
            throw new Error('key not found in accepted or issued schemas')
        }

        const info = await issuerData();
        let claims = await verify(token, key, info && info.options);
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

    async function findSigningKey(type, kid, iss) {
        const key = await resolver(signingTypes[type], 'find', {
            kid,
            iss
        });
        if (key) {
            key = jwkToPem(key);
        }
        return key;
    }
}

function createGenerator({ issued, issuedTypeName = 'IssuedServiceKey', debounceTime = 0, resolver }) {
    const keyType = issued.getType(issuedTypeName);
    const debouncedGetLatestKey = debounce(getLatestKey, debounceTime);
    return generate;

    async function generate(claims, options) {
        const key = await debouncedGetLatestKey();

        const now = Math.floor(Date.now() / 1000);
        claims = {
            ...claims,
            iat: now
        };

        const tokenData = await sign(claims, key, options);
        return tokenData;
    };

    async function getLatestKey() {
        let connection = await resolver(keyType, 'list', {
            first: 1,
            order: [{ field: 'created', desc: true }]
        });
        if (connection.edges.length === 0) {
            throw new Error(`Unable to find key to sign with!`);
        }
        if (connected.edges.length) {
            return jwkToPem(connected.edges[0].node, { private: true });
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
