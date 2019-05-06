module.exports = async function loadData({ schema, resolver, data }) {
    if (data == undefined) {
        return;
    }

    // Load data for every type specified
    await Promise.all(Object.keys(data).map(processType));

    async function processType(typeName) {
        const type = schema.getType(typeName);
        await Promise.all(data[typeName].map(entry => processDataEntry(type, entry)));
    }

    async function processDataEntry(type, entry) {
        const args = {
            ...entry.key,
            data: entry.data
        };
        await resolver(type, 'create', args);
    }
}
