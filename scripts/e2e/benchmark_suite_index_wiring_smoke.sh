#!/usr/bin/env bash
set -euo pipefail

mode="${1:-check}"
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "${mode}" in
  check|selftest) ;;
  *)
    echo "Usage: $0 [check|selftest]" >&2
    exit 64
    ;;
esac

if command -v bun >/dev/null 2>&1; then
  js_runtime="bun"
elif command -v node >/dev/null 2>&1; then
  js_runtime="node"
else
  echo "benchmark suite index wiring smoke requires bun or node" >&2
  exit 127
fi

cd "${root_dir}"

index_files=(
  "benchmarks/micro/index.js"
  "benchmarks/macro/index.js"
)

for index_file in "${index_files[@]}"; do
  if grep -Eq "simulateBenchmarkRun|For now|would normally|simulated result|Math\\.random\\(" "${index_file}"; then
    echo "benchmark suite index still contains simulated-result wiring: ${index_file}" >&2
    exit 1
  fi

  if ! grep -Fq "require.main === module" "${index_file}"; then
    echo "benchmark suite index is not directly executable: ${index_file}" >&2
    exit 1
  fi
done

js_source="$(cat <<'JS'
const assert = require('assert');

const micro = require('./benchmarks/micro/index.js');
const macro = require('./benchmarks/macro/index.js');

const expectedMicro = [
  ['arithmeticLoop', 'benchmarkIntegerArithmetic'],
  ['floatArithmetic', 'benchmarkFloatArithmetic'],
  ['propertyAccess', 'benchmarkPropertyAccess'],
  ['functionCalls', 'benchmarkFunctionCalls'],
  ['objectCreation', 'benchmarkObjectCreation'],
  ['arrayOperations', 'benchmarkArrayOperations'],
  ['stringOperations', 'benchmarkStringOperations'],
  ['jsonOperations', 'benchmarkJsonOperations'],
  ['closureCapture', 'benchmarkClosureCapture'],
  ['exceptionHandling', 'benchmarkExceptionHandling'],
  ['classInstantiation', 'benchmarkClassInstantiation'],
  ['miscOperations', 'benchmarkMiscOperations'],
];

const expectedMacro = [
  ['jsonTransformation', 'benchmarkJsonTransformation'],
  ['treeTraversal', 'benchmarkTreeTraversal'],
  ['recursiveAlgorithms', 'benchmarkRecursiveAlgorithms'],
  ['textProcessing', 'benchmarkTextProcessing'],
  ['eventEmitterSimulation', 'benchmarkEventEmitterSimulation'],
];

function assertLoadedFunctions(label, loaded, expected) {
  assert.deepStrictEqual(Object.keys(loaded), expected.map(([name]) => name), `${label} benchmark names drifted`);
  for (const [name, functionName] of expected) {
    assert.strictEqual(typeof loaded[name], 'function', `${label}.${name} is not a function`);
    assert.strictEqual(loaded[name].name, functionName, `${label}.${name} function name drifted`);
  }
}

async function assertRunAllExecutesRealFunction(label, Suite) {
  const suite = new Suite();
  let invoked = false;
  suite.benchmarks = {
    smoke: function smokeBenchmark() {
      invoked = true;
      return {
        duration: 1,
        operations: { smokeOps: 2 },
        opsPerSecond: { smokeOps: 2000 },
        results: { smoke: true },
      };
    },
  };

  const results = await suite.runAll();
  assert.strictEqual(invoked, true, `${label} runAll did not invoke the benchmark function`);
  assert.strictEqual(results.smoke.status, 'completed', `${label} smoke benchmark did not complete`);
  assert.strictEqual(results.smoke.module, 'smokeBenchmark', `${label} did not record the function identity`);
  assert.strictEqual(results.smoke.operations.smokeOps, 2, `${label} did not preserve benchmark metrics`);
}

(async () => {
  assertLoadedFunctions('micro', micro.loadMicroBenchmarkModules(), expectedMicro);
  assertLoadedFunctions('macro', macro.loadBenchmarkModules(), expectedMacro);
  await assertRunAllExecutesRealFunction('micro', micro.MicroBenchmarkSuite);
  await assertRunAllExecutesRealFunction('macro', macro.BenchmarkSuite);
  console.log('PASS benchmark suite index wiring smoke');
})().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
JS
)"

"${js_runtime}" -e "${js_source}"
