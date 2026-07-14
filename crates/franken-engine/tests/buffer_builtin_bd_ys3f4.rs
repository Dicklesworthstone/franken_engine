//! bd-ys3f4: Node-compatible `Buffer` core through `HybridRouter::eval`.
//!
//! The expected outputs below are pinned against Bun 1.3.14, the reference
//! runtime used by franken_node's compatibility corpus in
//! `crates/franken-node/tests/fixtures/compat_corpus/buffer/`.
//!
//! Coverage accounting:
//!
//! | Corpus cases | Requirements | Status |
//! | --- | ---: | --- |
//! | 0001-0027 | 27 | asserted through the public router |
//! | 0028-0030 | 3 | ignored follow-up: structured Node error objects/codes |
//!
//! The extra tests pin lowering/runtime invariants that the corpus depends on
//! but does not isolate: a local `Buffer` binding must shadow the global,
//! Buffers remain distinguishable from plain `Uint8Array` values while still
//! inheriting typed-array identity, slice/subarray views share backing bytes,
//! and backing-store bytes participate in the public engine memory budget.
//!
//! `HybridRouter` exposes only a completed `EvalOutcome` or an `EvalError`; a
//! memory-budget fault aborts the evaluation and exposes no post-failure heap
//! or accounting state. Consequently this public integration surface cannot
//! prove that failure while publishing the ArrayBuffer-plus-view pair leaves
//! no partial charge. That atomicity belongs in `baseline_interpreter` unit
//! coverage. The paired budget test below can still prove that an allocation
//! fits while a same-sized temporary byte copy is rejected under the same cap.

use frankenengine_engine::{EngineMemoryBudget, HybridRouter};

#[derive(Clone, Copy)]
struct CorpusCase {
    id: &'static str,
    source: &'static str,
    expected: &'static str,
}

fn try_eval_console(source: &str) -> Result<String, String> {
    let mut engine = HybridRouter::default();
    engine
        .eval(source)
        .map(|outcome| {
            outcome
                .console_output
                .iter()
                .map(|entry| entry.message.clone())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .map_err(|error| error.to_string())
}

fn eval_console(source: &str) -> String {
    try_eval_console(source).unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"))
}

fn assert_cases(cases: &[CorpusCase]) {
    let mut failures = Vec::new();

    for case in cases {
        match try_eval_console(case.source) {
            Ok(actual) if actual == case.expected => {}
            Ok(actual) => failures.push(format!(
                "{} output mismatch\n  expected: {:?}\n  actual:   {:?}",
                case.id, case.expected, actual
            )),
            Err(error) => failures.push(format!("{} eval failed: {error}", case.id)),
        }
    }

    assert!(
        failures.is_empty(),
        "{} Buffer conformance case(s) failed:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

const CORE_CORPUS_CASES: &[CorpusCase] = &[
    CorpusCase {
        id: "tc::buffer::0001",
        source: r#"
            const b = Buffer.from('hello', 'utf8');
            console.log(b.toString('hex'));
            console.log(b.length);
        "#,
        expected: "68656c6c6f\n5",
    },
    CorpusCase {
        id: "tc::buffer::0002",
        source: r#"
            const b = Buffer.from('68656c6c6f', 'hex');
            console.log(b.toString('utf8'));
            console.log(b.length);
        "#,
        expected: "hello\n5",
    },
    CorpusCase {
        id: "tc::buffer::0003",
        source: r#"
            const b = Buffer.from('aGVsbG8gd29ybGQ=', 'base64');
            console.log(b.toString('utf8'));
            console.log(Buffer.from('hello world').toString('base64'));
        "#,
        expected: "hello world\naGVsbG8gd29ybGQ=",
    },
    CorpusCase {
        id: "tc::buffer::0004",
        source: r#"
            const b = Buffer.from('café', 'latin1');
            console.log(b.toString('hex'));
            console.log(b.length);
        "#,
        expected: "636166e9\n4",
    },
    CorpusCase {
        id: "tc::buffer::0005",
        source: r#"
            const b = Buffer.from([104, 105, 33, 255]);
            console.log(b.toString('hex'));
            console.log(b[3]);
        "#,
        expected: "686921ff\n255",
    },
    CorpusCase {
        id: "tc::buffer::0006",
        source: r#"
            const ab = new ArrayBuffer(8);
            new Uint8Array(ab).set([1, 2, 3, 4, 5, 6, 7, 8]);
            const b = Buffer.from(ab, 2, 4);
            console.log(b.toString('hex'));
            console.log(b.length);
        "#,
        expected: "03040506\n4",
    },
    CorpusCase {
        id: "tc::buffer::0007",
        source: r#"
            const b = Buffer.from('héllo', 'utf8');
            console.log(b.toString('base64'));
            console.log(b.toString('hex'));
        "#,
        expected: "aMOpbGxv\n68c3a96c6c6f",
    },
    CorpusCase {
        id: "tc::buffer::0008",
        source: r#"
            const b = Buffer.from('abcdefgh');
            console.log(b.toString('utf8', 2, 5));
            console.log(b.toString('hex', 0, 3));
        "#,
        expected: "cde\n616263",
    },
    CorpusCase {
        id: "tc::buffer::0009",
        source: r#"
            const b = Buffer.alloc(5);
            console.log(b.toString('hex'));
            console.log(b.length);
        "#,
        expected: "0000000000\n5",
    },
    CorpusCase {
        id: "tc::buffer::0010",
        source: r#"
            console.log(Buffer.alloc(4, 0xab).toString('hex'));
            console.log(Buffer.alloc(6, 'ab').toString('utf8'));
        "#,
        expected: "abababab\nababab",
    },
    CorpusCase {
        id: "tc::buffer::0011",
        source: r#"
            const b = Buffer.allocUnsafe(8);
            console.log(b.length === 8);
            console.log(Buffer.isBuffer(b));
        "#,
        expected: "true\ntrue",
    },
    CorpusCase {
        id: "tc::buffer::0012",
        source: r#"
            const s = 'héllo€';
            console.log(Buffer.byteLength(s, 'utf8'));
            console.log(Buffer.byteLength(s, 'latin1'));
            console.log(s.length);
        "#,
        expected: "9\n6\n6",
    },
    CorpusCase {
        id: "tc::buffer::0013",
        source: r#"
            const a = Buffer.from('foo'), b = Buffer.from('bar'), c = Buffer.from('baz');
            const all = Buffer.concat([a, b, c]);
            console.log(all.toString('utf8'));
            console.log(Buffer.concat([a, b], 4).toString('utf8'));
            console.log(all.length);
        "#,
        expected: "foobarbaz\nfoob\n9",
    },
    CorpusCase {
        id: "tc::buffer::0014",
        source: r#"
            const b = Buffer.from('abcdef');
            const s = b.slice(1, 4);
            s[0] = 0x58;
            console.log(b.toString('utf8'));
            console.log(s.toString('utf8'));
        "#,
        expected: "aXcdef\nXcd",
    },
    CorpusCase {
        id: "tc::buffer::0015",
        source: r#"
            const b = Buffer.from('abcdef');
            const s = b.subarray(2, 5);
            b[2] = 0x5a;
            console.log(s.toString('utf8'));
            console.log(s.length);
        "#,
        expected: "Zde\n3",
    },
    CorpusCase {
        id: "tc::buffer::0016",
        source: r#"
            const b = Buffer.from('hello hello');
            console.log(b.indexOf('llo'));
            console.log(b.indexOf('llo', 4));
            console.log(b.indexOf(0x6c));
            console.log(b.indexOf('zzz'));
            console.log(b.includes('hello'));
            console.log(b.includes('nope'));
        "#,
        expected: "2\n8\n2\n-1\ntrue\nfalse",
    },
    CorpusCase {
        id: "tc::buffer::0017",
        source: r#"
            const a = Buffer.from('abc');
            console.log(a.equals(Buffer.from('abc')));
            console.log(a.equals(Buffer.from('abd')));
            console.log(a.equals(Buffer.from('ab')));
        "#,
        expected: "true\nfalse\nfalse",
    },
    CorpusCase {
        id: "tc::buffer::0018",
        source: r#"
            const a = Buffer.from('abc'), b = Buffer.from('abd');
            console.log(Buffer.compare(a, b));
            console.log(Buffer.compare(b, a));
            console.log(Buffer.compare(a, Buffer.from('abc')));
            console.log(a.compare(b));
        "#,
        expected: "-1\n1\n0\n-1",
    },
    CorpusCase {
        id: "tc::buffer::0019",
        source: r#"
            const b = Buffer.alloc(3);
            b.writeUInt8(0xff, 0);
            b.writeUInt8(1, 2);
            console.log(b.readUInt8(0));
            console.log(b.toString('hex'));
        "#,
        expected: "255\nff0001",
    },
    CorpusCase {
        id: "tc::buffer::0020",
        source: r#"
            const b = Buffer.alloc(2);
            b.writeUInt16LE(0x1234, 0);
            console.log(b.toString('hex'));
            console.log(b.readUInt16LE(0));
            console.log(b.readUInt16BE(0));
        "#,
        expected: "3412\n4660\n13330",
    },
    CorpusCase {
        id: "tc::buffer::0021",
        source: r#"
            const b = Buffer.alloc(4);
            b.writeInt32BE(-2, 0);
            console.log(b.toString('hex'));
            console.log(b.readInt32BE(0));
            console.log(b.readUInt32BE(0));
        "#,
        expected: "fffffffe\n-2\n4294967294",
    },
    CorpusCase {
        id: "tc::buffer::0022",
        source: r#"
            const src = Buffer.from('abcdef');
            const dst = Buffer.from('123456');
            const n = src.copy(dst, 1, 2, 5);
            console.log(dst.toString('utf8'));
            console.log(n);
        "#,
        expected: "1cde56\n3",
    },
    CorpusCase {
        id: "tc::buffer::0023",
        source: r#"
            console.log(Buffer.isBuffer(Buffer.from('x')));
            console.log(Buffer.isBuffer(new Uint8Array(2)));
            console.log(Buffer.isBuffer('str'));
        "#,
        expected: "true\nfalse\nfalse",
    },
    CorpusCase {
        id: "tc::buffer::0024",
        source: r#"
            const j = Buffer.from([1, 2, 255]).toJSON();
            console.log(j.type);
            console.log(j.data.join(','));
        "#,
        expected: "Buffer\n1,2,255",
    },
    CorpusCase {
        id: "tc::buffer::0025",
        source: r#"
            const b = Buffer.from([10, 20, 30]);
            console.log([...b.keys()].join(','));
            console.log([...b.values()].join(','));
            console.log([...b.entries()].map(e => e.join(':')).join(','));
        "#,
        expected: "0,1,2\n10,20,30\n0:10,1:20,2:30",
    },
    CorpusCase {
        id: "tc::buffer::0026",
        source: r#"
            const b = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
            b.swap16();
            console.log(b.toString('hex'));
            b.swap32();
            console.log(b.toString('hex'));
        "#,
        expected: "0201040306050807\n0304010207080506",
    },
    CorpusCase {
        id: "tc::buffer::0027",
        source: r#"
            const b = Buffer.from([251, 255, 190]);
            console.log(b.toString('base64'));
            console.log(b.toString('base64url'));
            console.log(Buffer.from('-_-_', 'base64url').toString('hex'));
        "#,
        expected: "+/++\n-_--\nfbffbf",
    },
];

#[test]
fn core_buffer_corpus_0001_through_0027_matches_bun() {
    assert_cases(CORE_CORPUS_CASES);
}

#[test]
fn direct_buffer_spread_consumes_the_byte_iterator() {
    assert_eq!(
        eval_console("console.log([...Buffer.from([1, 2])].join(','));"),
        "1,2"
    );
}

#[test]
fn buffer_alloc_validates_size_before_fractional_truncation() {
    let source = r#"
        function rejectsMissing() {
          try { Buffer.alloc(); return false; }
          catch (error) { return error instanceof TypeError; }
        }
        function rejectsSize(value) {
          try { Buffer.alloc(value); return false; }
          catch (error) { return error instanceof TypeError; }
        }
        console.log(rejectsMissing());
        console.log(rejectsSize(undefined));
        console.log(rejectsSize('3'));
        console.log(rejectsSize(true));
        console.log(rejectsSize(null));
        console.log(rejectsSize(3n));
        console.log(Buffer.alloc(3.9).length);
    "#;
    assert_eq!(
        eval_console(source),
        "true\ntrue\ntrue\ntrue\ntrue\ntrue\n3"
    );
}

#[test]
fn buffer_concat_validates_and_truncates_an_explicit_total_length() {
    let source = r#"
        const chunks = [Buffer.from('abcd')];
        function rejectsType(value) {
          try { Buffer.concat(chunks, value); return false; }
          catch (error) { return error instanceof TypeError; }
        }
        function rejectsRange(value) {
          try { Buffer.concat(chunks, value); return false; }
          catch (error) { return error instanceof RangeError; }
        }
        console.log(rejectsType('2'));
        console.log(rejectsType(true));
        console.log(rejectsType(null));
        console.log(rejectsType(2n));
        console.log(rejectsRange(Infinity));
        console.log(rejectsRange(-1));
        console.log(Buffer.concat(chunks, NaN).length);
        console.log(Buffer.concat(chunks, 2.9).toString());
        console.log(Buffer.concat(chunks, undefined).toString());
    "#;
    assert_eq!(
        eval_console(source),
        "true\ntrue\ntrue\ntrue\ntrue\ntrue\n0\nab\nabcd"
    );
}

#[test]
fn buffer_byte_length_handles_invalid_encodings_estimates_and_binary_views() {
    let source = r#"
        const backing = new ArrayBuffer(5);
        console.log(Buffer.byteLength('😀', 'not-an-encoding'));
        console.log(Buffer.byteLength('😀', null));
        console.log(Buffer.byteLength('😀', 42));
        console.log(Buffer.byteLength('😀', true));
        console.log(Buffer.byteLength('😀', {}));
        try {
          Buffer.from('😀', 'not-an-encoding');
          console.log(false);
        } catch (error) {
          console.log(error instanceof TypeError);
        }
        try {
          Buffer.from('😀').toString('not-an-encoding');
          console.log(false);
        } catch (error) {
          console.log(error instanceof TypeError);
        }
        console.log(Buffer.byteLength('YQ==Yg==', 'base64'));
        console.log(Buffer.byteLength(backing));
        console.log(Buffer.byteLength(new DataView(backing, 1, 3)));
        console.log(Buffer.byteLength(new Int32Array(3)));
    "#;
    assert_eq!(
        eval_console(source),
        "4\n4\n4\n4\n4\ntrue\ntrue\n4\n5\n3\n12"
    );
}

#[test]
fn buffer_search_accepts_encoding_as_the_second_argument() {
    let source = r#"
        const b = Buffer.from('hello');
        console.log(b.indexOf('68', 'hex'));
        console.log(b.includes('68', 'hex'));
        console.log(b.indexOf('6c', 'hex'));
        console.log(b.includes('6c', 'hex'));
    "#;
    assert_eq!(eval_console(source), "0\ntrue\n2\ntrue");
}

#[test]
fn buffer_copy_rejects_source_start_past_the_end_without_mutation() {
    let source = r#"
        const src = Buffer.from('ab');
        const dst = Buffer.from('zz');
        try {
          src.copy(dst, 0, 3);
          console.log(false);
        } catch (error) {
          console.log(error instanceof RangeError);
        }
        console.log(dst.toString());
    "#;
    assert_eq!(eval_console(source), "true\nzz");
}

#[test]
fn instance_buffer_compare_honors_target_and_source_ranges() {
    let source = r#"
        const source = Buffer.from('abcdef');
        console.log(source.compare(Buffer.from('xxcdey'), 2, 5, 2, 5));
        console.log(source.compare(Buffer.from('xxcdfy'), 2, 5, 2, 5));
        console.log(source.compare(Buffer.from('xxcddy'), 2, 5, 2, 5));
        console.log(source.compare(Buffer.from('zz'), 0, 0, 0, 0));
        console.log(source.compare(Buffer.from('zz'), 0, 2, 6, 6));
        console.log(source.compare(Buffer.from('zz'), 2, 2, 0, 2));
    "#;
    assert_eq!(eval_console(source), "0\n-1\n1\n0\n-1\n1");
}

#[test]
fn buffer_apis_reject_bigint_inputs_without_mutation() {
    let source = r#"
        function rejectsFrom() {
          try { Buffer.from([1n]); return false; }
          catch (error) { return error instanceof TypeError; }
        }
        function rejectsFill() {
          try { Buffer.alloc(2, 1n); return false; }
          catch (error) { return error instanceof TypeError; }
        }
        const b = Buffer.from([7]);
        function rejectsWrite() {
          try { b.writeUInt8(1n, 0); return false; }
          catch (error) { return error instanceof TypeError; }
        }
        console.log(rejectsFrom());
        console.log(rejectsFill());
        console.log(rejectsWrite());
        console.log(b.toString('hex'));
    "#;
    assert_eq!(eval_console(source), "true\ntrue\ntrue\n07");
}

#[test]
fn fresh_eyes_encoding_and_bounds_regressions_match_bun() {
    let cases = [
        CorpusCase {
            id: "buffer-to-string-negative-bounds",
            source: r#"
                const b = Buffer.from('abcdef');
                console.log(JSON.stringify(b.toString('utf8', -2)));
                console.log(JSON.stringify(b.toString('utf8', 0, -2)));
                console.log(JSON.stringify(b.toString('utf8', -3, 3)));
                console.log(JSON.stringify(b.toString('utf8', 4, -1)));
            "#,
            expected: "\"abcdef\"\n\"\"\n\"abc\"\n\"\"",
        },
        CorpusCase {
            id: "buffer-from-int32array-narrows-elements",
            source: r#"
                console.log(Buffer.from(new Int32Array([-1, 256])).toString('hex'));
            "#,
            expected: "ff00",
        },
        CorpusCase {
            id: "buffer-latin1-uses-utf16-code-units",
            source: r#"
                console.log(Buffer.from('😀', 'latin1').toString('hex'));
                console.log(Buffer.byteLength('😀', 'latin1'));
            "#,
            expected: "3d00\n2",
        },
        CorpusCase {
            id: "buffer-base64-is-forgiving-and-alphabet-agnostic",
            source: r#"
                console.log(Buffer.from('+/_-', 'base64').toString('hex'));
                console.log(Buffer.from(' +/ $_-!!\n', 'base64').toString('hex'));
                console.log(Buffer.from('YW$Jj\nZA==!!', 'base64').toString('utf8'));
            "#,
            expected: "fbfffe\nfbfffe\nabcd",
        },
        CorpusCase {
            id: "buffer-base64-stops-at-first-padding",
            source: r#"
                console.log(Buffer.from('YQ==Yg==', 'base64').toString('hex'));
            "#,
            expected: "61",
        },
        CorpusCase {
            id: "buffer-write-uint8-coerces-fractional-and-non-finite-values",
            source: r#"
                const b = Buffer.alloc(3, 9);
                b.writeUInt8(1.5, 0);
                b.writeUInt8(NaN, 1);
                b.writeUInt8(undefined, 2);
                console.log(b.toString('hex'));
            "#,
            expected: "010000",
        },
    ];

    assert_cases(&cases);
}

#[test]
fn local_buffer_binding_shadows_the_global_builtin() {
    let source = r#"
        const Buffer = {
          from: (value) => 'local:' + value,
          isBuffer: () => 'local-check'
        };
        console.log(Buffer.from('x'));
        console.log(Buffer.isBuffer({}));
    "#;
    assert_eq!(eval_console(source), "local:x\nlocal-check");
}

#[test]
fn buffer_is_distinct_from_a_plain_uint8array() {
    let source = r#"
        const b = Buffer.from([1, 2]);
        const u = new Uint8Array(2);
        console.log(Buffer.isBuffer(b));
        console.log(Buffer.isBuffer(u));
    "#;
    assert_eq!(eval_console(source), "true\nfalse");
}

#[test]
fn guest_properties_cannot_forge_or_remove_buffer_identity() {
    let source = r#"
        const plain = new Uint8Array(1);
        plain.__isBuffer = true;
        const buffer = Buffer.from([1]);
        buffer.__isBuffer = false;
        console.log(Buffer.isBuffer(plain));
        console.log(Buffer.isBuffer(buffer));
        console.log(String(plain.__isBuffer));
        console.log(String(buffer.__isBuffer));
    "#;
    assert_eq!(eval_console(source), "false\ntrue\ntrue\nfalse");
}

#[test]
fn slice_and_subarray_share_one_backing_store() {
    let source = r#"
        const b = Buffer.from([1, 2, 3, 4]);
        const slice = b.slice(1, 3);
        const subarray = b.subarray(2, 4);
        slice[1] = 9;
        subarray[1] = 8;
        console.log(b.toString('hex'));
        console.log(slice.toString('hex'));
        console.log(subarray.toString('hex'));
    "#;
    assert_eq!(eval_console(source), "01020908\n0209\n0908");
}

#[test]
fn buffer_backing_bytes_obey_the_public_memory_budget() {
    const SOURCE: &str = "const b = Buffer.alloc(1048576); console.log(b.length);";

    let mut tight_router = HybridRouter::default();
    let tight = tight_router.eval_with_budgets(
        SOURCE,
        None,
        Some(EngineMemoryBudget {
            max_heap_objects: 10_000,
            max_total_memory_bytes: 256 * 1024,
        }),
    );
    let error = tight.expect_err("a 1 MiB Buffer must fail under a 256 KiB memory budget");
    let rendered = error.to_string().to_lowercase();
    assert!(
        rendered.contains("memory budget")
            || rendered.contains("total memory")
            || rendered.contains("total cap"),
        "expected a memory-budget failure, got: {error}"
    );

    let mut generous_router = HybridRouter::default();
    let outcome = generous_router
        .eval_with_budgets(
            SOURCE,
            None,
            Some(EngineMemoryBudget {
                max_heap_objects: 10_000,
                max_total_memory_bytes: 4 * 1024 * 1024,
            }),
        )
        .expect("the same 1 MiB Buffer must fit under a 4 MiB memory budget");
    let actual = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(actual, "1048576");
}

#[test]
fn buffer_temporary_copy_obeys_the_public_memory_budget() {
    const FOUR_MIB: usize = 4 * 1024 * 1024;
    const SIX_MIB: u64 = 6 * 1024 * 1024;
    let budget = EngineMemoryBudget {
        max_heap_objects: 10_000,
        max_total_memory_bytes: SIX_MIB,
    };

    let mut allocation_router = HybridRouter::default();
    let allocated = allocation_router
        .eval_with_budgets(
            &format!("const b = Buffer.alloc({FOUR_MIB}); console.log(b.length);"),
            None,
            Some(budget),
        )
        .expect("a 4 MiB Buffer must fit under the 6 MiB cap before temporary copying");
    let allocated_output = allocated
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(allocated_output, FOUR_MIB.to_string());

    let mut copying_router = HybridRouter::default();
    let copied = copying_router.eval_with_budgets(
        &format!("const b = Buffer.alloc({FOUR_MIB}); console.log(b.toString('hex').length);"),
        None,
        Some(budget),
    );
    let error = copied
        .expect_err("the additional 4 MiB temporary copy must exceed the same 6 MiB memory cap");
    let rendered = error.to_string().to_lowercase();
    assert!(
        rendered.contains("memory budget")
            || rendered.contains("total memory")
            || rendered.contains("total cap"),
        "expected a temporary-memory budget failure, got: {error}"
    );
}

#[test]
fn buffer_iterator_spread_obeys_the_public_memory_budget() {
    const ONE_MIB: usize = 1024 * 1024;
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let budget = EngineMemoryBudget {
        max_heap_objects: 10_000,
        max_total_memory_bytes: TWO_MIB,
    };

    let mut allocation_router = HybridRouter::default();
    let allocated = allocation_router
        .eval_with_budgets(
            &format!("const b = Buffer.alloc({ONE_MIB}); console.log(b.length);"),
            None,
            Some(budget),
        )
        .expect("a 1 MiB Buffer must fit under the 2 MiB cap before iterator expansion");
    let allocated_output = allocated
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(allocated_output, ONE_MIB.to_string());

    let mut spreading_router = HybridRouter::default();
    let spread = spreading_router.eval_with_budgets(
        &format!("const b = Buffer.alloc({ONE_MIB}); console.log([...b].length);"),
        None,
        Some(budget),
    );
    let error = spread
        .expect_err("materializing a 1 MiB Buffer iterator must exceed the same 2 MiB memory cap");
    let rendered = error.to_string().to_lowercase();
    assert!(
        rendered.contains("memory budget")
            || rendered.contains("total memory")
            || rendered.contains("total cap"),
        "expected an iterator-spread memory-budget failure, got: {error}"
    );
}

#[test]
fn integer_writes_reject_out_of_range_values_before_mutation() {
    let source = r#"
        const b = Buffer.from([1, 2, 3, 4]);
        try { b.writeUInt8(256, 0); } catch (e) { console.log(e instanceof RangeError); }
        try { b.writeUInt16LE(-1, 0); } catch (e) { console.log(e instanceof RangeError); }
        try { b.writeInt32BE(2147483648, 0); } catch (e) { console.log(e instanceof RangeError); }
        try { b.writeUInt32LE(-1, 0); } catch (e) { console.log(e instanceof RangeError); }
        console.log(b.toString('hex'));
    "#;
    assert_eq!(eval_console(source), "true\ntrue\ntrue\ntrue\n01020304");
}

#[test]
fn buffer_copy_infinite_bounds_coerce_to_zero_but_finite_negatives_throw() {
    let source = r#"
        const src = Buffer.from('abcd');
        function run(targetStart, sourceStart, sourceEnd) {
          const dst = Buffer.from('1234');
          try {
            console.log(src.copy(dst, targetStart, sourceStart, sourceEnd));
          } catch (error) {
            console.log(error instanceof RangeError);
          }
          console.log(dst.toString('utf8'));
        }
        run(Infinity, 0, 2);
        run(-Infinity, 0, 2);
        run(0, Infinity, 2);
        run(0, -Infinity, 2);
        run(0, 0, Infinity);
        run(0, 0, -Infinity);
        run(-1, 0, 2);
        run(0, -1, 2);
        run(0, 0, -1);
    "#;
    assert_eq!(
        eval_console(source),
        "2\nab34\n2\nab34\n2\nab34\n2\nab34\n0\n1234\n0\n1234\ntrue\n1234\ntrue\n1234\ntrue\n1234"
    );
}

#[test]
#[ignore = "bd-ys3f4 follow-up: structured Node Buffer error objects/codes"]
fn structured_node_error_codes_0028_through_0030() {
    let cases = [
        CorpusCase {
            id: "tc::buffer::0028",
            source: r#"
                try {
                  Buffer.from('abc').toString('bogus');
                  console.log('no-throw');
                } catch (e) {
                  console.log(e instanceof TypeError);
                  console.log(String(e.code));
                }
            "#,
            expected: "true\nERR_UNKNOWN_ENCODING",
        },
        CorpusCase {
            id: "tc::buffer::0029",
            source: r#"
                try {
                  Buffer.alloc(-1);
                  console.log('no-throw');
                } catch (e) {
                  console.log(e instanceof RangeError);
                  console.log(String(e.code));
                }
            "#,
            expected: "true\nERR_OUT_OF_RANGE",
        },
        CorpusCase {
            id: "tc::buffer::0030",
            source: r#"
                const b = Buffer.alloc(2);
                try {
                  b.readUInt32LE(0);
                  console.log('no-throw');
                } catch (e) {
                  console.log(e instanceof RangeError);
                  console.log(String(e.code));
                }
            "#,
            expected: "true\nERR_BUFFER_OUT_OF_BOUNDS",
        },
    ];

    assert_cases(&cases);
}
