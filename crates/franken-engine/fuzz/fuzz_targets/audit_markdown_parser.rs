#![no_main]

use frankenengine_engine::audit_closure_matrix::AuditClosureMatrix;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 32 * 1024;
const MAX_SYNTHETIC_ROWS: usize = 64;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(content) = std::str::from_utf8(data) {
        exercise_parser(content);
    }

    let lossy_content = String::from_utf8_lossy(data);
    exercise_parser(&lossy_content);

    let synthetic_table = synthetic_markdown_table(data);
    exercise_parser(&synthetic_table);
});

fn exercise_parser(content: &str) {
    let first = AuditClosureMatrix::parse_from_markdown(content);
    let second = AuditClosureMatrix::parse_from_markdown(content);

    match (first, second) {
        (Ok(first_matrix), Ok(second_matrix)) => {
            assert_eq!(
                first_matrix.total_closures(),
                second_matrix.total_closures()
            );
            assert_eq!(
                first_matrix.get_finding_ids(),
                second_matrix.get_finding_ids()
            );
            let _ = first_matrix.validate_completeness();
        }
        (Err(first_error), Err(second_error)) => {
            assert_eq!(first_error.to_string(), second_error.to_string());
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            panic!("audit closure markdown parser produced nondeterministic results");
        }
    }
}

fn synthetic_markdown_table(data: &[u8]) -> String {
    let mut table = String::from(
        "| Finding ID | Fixing Bead | File Path | Test Coverage | Artifact |\n\
         | --- | --- | --- | --- | --- |\n",
    );

    for (row_index, row) in data.chunks(5).take(MAX_SYNTHETIC_ROWS).enumerate() {
        let finding_suffix = row.first().copied().unwrap_or(row_index as u8);
        let finding_id = if row.get(1).copied().unwrap_or(0) & 1 == 0 {
            format!("RGC-{finding_suffix:03}.{}", row_index % 8)
        } else {
            cell_text(row, "finding")
        };
        let fixing_bead = format!("bd-{}", cell_text(row, "bead"));
        let file_path = format!("src/{}.rs", cell_text(row, "file"));
        let test_coverage = cell_text(row, "test");
        let artifact = cell_text(row, "artifact");

        table.push_str(&format!(
            "| {finding_id} | {fixing_bead} | {file_path} | {test_coverage} | {artifact} |\n"
        ));
    }

    table
}

fn cell_text(bytes: &[u8], fallback: &str) -> String {
    let mut text = String::new();
    for byte in bytes.iter().copied().take(24) {
        let ch = match byte {
            b'|' | b'\n' | b'\r' => '_',
            0x20..=0x7e => byte as char,
            _ => char::from(b'a' + (byte % 26)),
        };
        text.push(ch);
    }

    if text.is_empty() {
        fallback.to_string()
    } else {
        text
    }
}
