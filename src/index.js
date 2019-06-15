module.exports = createServiceContextCreator;

const createContextCreator = require(`./context.js`);
const { validator: createTokenValidator, generator: createTokenGenerator } = require(`./token.js`);

async function createServiceContextCreator({ schema,
                                             loadIssuerData,
                                             contextOptions,
                                             fetchSigningKeyThrottle,
                                             fetchValidationKeyThrottle }) {

    const createLogger = contextOptions && contextOptions.createLogger || defaultCreateLogger;
    const createStat = contextOptions && contextOptions.createStat || defaultCreateStat;

    const tokenValidator = createTokenValidator({
        schema,
        loadIssuerData,
        createContext: createInternalContext,
        keyFetchThrottleTime: fetchValidationKeyThrottle
    });

    const tokenGenerator = createTokenGenerator({
        schema,
        createContext: createInternalContext,
        keyFetchThrottleTime: fetchSigningKeyThrottle
    });

    const createContext = createContextCreator({
        ...contextOptions,
        verifyRequestToken: tokenValidator,
        generateToken: tokenGenerator
    });
    return createContext;

    function createInternalContext() {
        return {
            log: createLogger(),
            stat: createStat()
        };
    }

    function defaultCreateLogger() {
        return console;
    }

    function defaultCreateStat() {
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
}
