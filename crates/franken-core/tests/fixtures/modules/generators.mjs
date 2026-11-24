const owner = 'owner';

export function* importedValues(value) {
    const next = yield owner + ':' + value;
    yield value + next;
    return value + next + 1;
}
