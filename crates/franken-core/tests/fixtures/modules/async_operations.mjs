export async function delayed(value) {
    const result = await new Promise(resolve => setTimeout(resolve, 0, value));
    return result + 1;
}
