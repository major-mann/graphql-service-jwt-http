module.exports = createService;

const serviceHelper = require('@major-mann/graphql-helpers-service');
const createContextCreator = require('./context.js');
const { validator: createTokenValidator, generator: createTokenGenerator } = require('./token.js');
const loadMasterData = require('./master-data-loader.js');

function createService({ schema, loadIssuerData, contextOptions, serviceKeyOptions, fetchSigningKeyDebounce, masterData }) {
    const INTERNAL_USER = Symbol('internal-user');
    const INTERNAL_ISSUER = Symbol('internal-issuer');

    const createLogger = contextOptions && contextOptions.createLogger || (() => console);

    const resolver = serviceHelper.graph({
        createInfo: () => ({}),
        createSource: () => ({}),
        createContext: createInternalContext
    });

    const tokenValidator = createTokenValidator({
        resolver,
        loadIssuerData,
        issued: schema,
        accepted: schema,
        acceptedTypeName: serviceKeyOptions && serviceKeyOptions.acceptedKeyTypeName,
        issuedTypeName: serviceKeyOptions && serviceKeyOptions.issuedKeyTypeName
    });

    const tokenGenerator = createTokenGenerator({
        issued: schema,
        debounceTime: fetchSigningKeyDebounce,
        issuedTypeName: serviceKeyOptions && serviceKeyOptions.issuedKeyTypeName
    });

    const createContext = createContextCreator({
        ...contextOptions,
        verifyRequestToken: tokenValidator,
        generateToken: (issuer, claims) => tokenGenerator({
            ...claims,
            iss: issuer
        })
    });

    if (masterData) {
        await loadMasterData({
            schema,
            resolver,
            data: masterData
        });
    }

    return {
        resolver,
        createContext,
        token: {
            validate: (token, context) => tokenValidator(token, context || createInternalContext()),
            generate: (claims, options) => tokenGenerator(claims, options),
        },
        isInternalUser: sub => sub === INTERNAL_USER,
        isInternalIssuer: iss => iss === INTERNAL_ISSUER
    };

    function createInternalContext() {
        const user = {
            sub: INTERNAL_USER,
            iss: INTERNAL_ISSUER
        };
        return {
            user,
            issuer: undefined,
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
}
