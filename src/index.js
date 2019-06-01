module.exports = createServiceContextCreator;

const serviceHelper = require('@major-mann/graphql-helpers-service');
const createContextCreator = require('./context.js');
const { validator: createTokenValidator, generator: createTokenGenerator } = require('./token.js');

async function createServiceContextCreator({ schema,
                                             issuer,
                                             loadIssuerData,
                                             contextOptions,
                                             fetchSigningKeyDebounce,
                                             fetchValidationKeyDebounce }) {

    const INTERNAL_USER = Symbol('internal-user');
    const INTERNAL_ISSUER = Symbol('internal-issuer');

    const createLogger = contextOptions && contextOptions.createLogger || (() => console);

    const tokenValidator = createTokenValidator({
        schema,
        loadIssuerData,
        createContext: createInternalContext,
        keyFetchDebounceTime: fetchValidationKeyDebounce
    });

    const tokenGenerator = createTokenGenerator({
        schema,
        keyFetchDebounceTime: fetchSigningKeyDebounce
    });

    const createContext = createContextCreator({
        ...contextOptions,
        isInternalUser,
        isInternalIssuer,
        verifyRequestToken: tokenValidator,
        generateToken: (issuer, claims) => tokenGenerator({
            ...claims,
            iss: issuer
        })
    });

    return createContext;

    function createInternalContext() {
        const user = {
            sub: INTERNAL_USER,
            iss: INTERNAL_ISSUER
        };
        return {
            user,
            isInternalUser,
            isInternalIssuer,
            issuer: INTERNAL_ISSUER,
            log: createLogger(undefined, user),
            stat: {
                increment: () => undefined,
                decrement: () => undefined,
                counter: () => undefined,
                gauge: () => undefined,
                gaugeDelta: () => undefined,
                set: () => undefined,
                histogram: () => undefined,
            }
        };
    }

    function isInternalUser(sub) {
        return sub === INTERNAL_USER;
    }

    function isInternalIssuer(iss) {
        return iss === INTERNAL_ISSUER;
    }
}
