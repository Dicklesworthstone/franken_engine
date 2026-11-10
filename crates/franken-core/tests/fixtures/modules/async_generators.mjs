const owner = 'owner';

export async function* importedValues(value) {
    const next = await new Promise(resolve => setTimeout(resolve, 0, value + 1));
    yield owner + ':' + next;
    return next + 1;
}
