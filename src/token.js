module.exports = {
    validator: createValidator,
    generator: createGenerator
};

const jwt = require('jsonwebtoken');

function createValidator({ accepted,
                           issued,
                           resolver,
                           loadIssuerData,
                           acceptedTypeName = 'AcceptedServiceKeyQuery',
                           issuedTypeName = 'IssuedServiceKeyQuery' }) {
    return function validator(token, context) {
        const decoded = jwt.decode(token, { complete: true });

        let key;
        if (accepted) {
            key = await search(accepted.getType(acceptedTypeName));
        }
        if (!key && issued) {
            key = await search(issued.getType(issuedTypeName));
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

        function search(type) {
            return resolver(type, 'find', {
                kid: decoded.header.kid || decoded.payload.kid,
                iss: decoded.payload.iss
            });
        }

        async function issuerData() {
            if (typeof loadIssuerData === 'function') {
                const data = await loadIssuerData(decoded.payload.iss, context);
                return data;
            } else {
                return undefined;
            }
        }
    };
}

function createGenerator({ issued, issuedTypeName = 'IssuedServiceKey', debounceTime = 0 }) {
    let debounce;
    return async function generate(claims, options) {
        const key = await debouncedSearch();

        const now = Math.floor(Date.now() / 1000);
        claims = {
            ...claims,
            iat: now
        };

        const tokenData = await sign(claims, key, options);
        return tokenData;
    };

    async function debouncedSearch() {
        if (!debounceTime) {
            return search();
        }
        if (debounce) {
            return debounce;
        }
        debounce = search();
        setTimeout(() => debounce = undefined, debounceTime);
        return debounce;
    }

    async function search() {
        let connection = await resolver(issued.getType(issuedTypeName), 'list', {
            first: 1,
            order: [{ field: 'created', desc: true }]
        });
        if (connection.edges.length === 0) {
            throw new Error(`Unable to find key to sign with in ${issuedTypeName}`);
        }
        return connected.edges[0].node;
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
