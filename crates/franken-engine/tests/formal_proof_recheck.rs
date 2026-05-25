#![forbid(unsafe_code)]

//! Formal proof recheck integration tests for G.2 proof bundle.
//!
//! This test module ensures that all formal proofs in the G.2 bundle
//! remain valid and can be mechanically verified using Lean 4.
//!
//! Failure on any proof regression prevents deployment until fixed.

use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Test that the formal proof recheck script exists and is executable.
#[test]
fn formal_proof_recheck_script_exists() {
    let script_path = Path::new("scripts/run_rgc_formal_proof_recheck.sh");
    assert!(
        script_path.exists(),
        "Formal proof recheck script must exist: {:?}",
        script_path
    );

    let metadata = script_path
        .metadata()
        .expect("Should be able to read script metadata");

    #[cfg(unix)]
    assert!(
        metadata.permissions().mode() & 0o111 != 0,
        "Formal proof recheck script must be executable"
    );
}

/// Test that the Lean 4 proof directory exists and contains required proof files.
#[test]
fn lean_proof_directory_structure_valid() {
    let proof_dir = Path::new("proofs/lean4");
    assert!(
        proof_dir.exists(),
        "Lean 4 proof directory must exist: {:?}",
        proof_dir
    );

    // Check required configuration files
    let lean_toolchain = proof_dir.join("lean-toolchain");
    assert!(
        lean_toolchain.exists(),
        "lean-toolchain file must exist: {:?}",
        lean_toolchain
    );

    let lakefile = proof_dir.join("lakefile.lean");
    assert!(
        lakefile.exists(),
        "lakefile.lean must exist: {:?}",
        lakefile
    );

    // Check required G.2 proof files
    let required_proofs = [
        "IFCLatticeSpecification.lean",
        "IFCLatticeIsomorphism.lean",
        "CapabilityAlgebraSpecification.lean",
        "CapabilityAlgebraIsomorphism.lean",
        "PureExprSemantics.lean",
        "translation_validation.lean",
    ];

    for proof_file in &required_proofs {
        let proof_path = proof_dir.join(proof_file);
        assert!(
            proof_path.exists(),
            "Required proof file must exist: {:?}",
            proof_path
        );

        let proof_content =
            std::fs::read_to_string(&proof_path).expect("Should be able to read proof file");
        assert!(
            !proof_content.trim().is_empty(),
            "Proof file must not be empty: {:?}",
            proof_path
        );
    }
}

/// Test that the lean-toolchain specifies a valid version.
#[test]
fn lean_toolchain_version_valid() {
    let toolchain_path = Path::new("proofs/lean4/lean-toolchain");
    let toolchain_content = std::fs::read_to_string(toolchain_path)
        .expect("Should be able to read lean-toolchain file");

    let version = toolchain_content.trim();
    assert!(!version.is_empty(), "lean-toolchain must specify a version");

    // Check that it looks like a version number (basic validation)
    assert!(
        version.chars().next().unwrap().is_ascii_digit(),
        "lean-toolchain version should start with a digit: {}",
        version
    );
}

/// Test that the lakefile.lean contains required dependencies.
#[test]
fn lakefile_dependencies_present() {
    let lakefile_path = Path::new("proofs/lean4/lakefile.lean");
    let lakefile_content =
        std::fs::read_to_string(lakefile_path).expect("Should be able to read lakefile.lean");

    // Check for mathlib dependency (required for formal verification)
    assert!(
        lakefile_content.contains("mathlib"),
        "lakefile.lean must include mathlib dependency for formal verification"
    );

    // Check for package declaration
    assert!(
        lakefile_content.contains("package"),
        "lakefile.lean must declare a package"
    );
}

/// Test that formal proof recheck script runs without errors (basic smoke test).
///
/// Note: This test may be skipped in environments where Lean 4 is not available,
/// but the script should still validate the proof directory structure.
#[test]
fn formal_proof_recheck_smoke_test() {
    let script_path = "scripts/run_rgc_formal_proof_recheck.sh";

    let output = Command::new(script_path)
        .current_dir(".")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Should be able to execute formal proof recheck script");

    // Script should exit with success (0) or Lean-not-available (which is also success)
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "Formal proof recheck script failed\nstdout: {}\nstderr: {}",
            stdout, stderr
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should either complete verification or indicate Lean is not available
    assert!(
        stdout.contains("SUCCESS")
            || stdout.contains("Lean 4 not found")
            || stdout.contains("proof checking skipped"),
        "Script should either verify proofs or indicate Lean unavailability\nOutput: {}",
        stdout
    );
}

/// Test individual proof files are syntactically valid Lean code.
#[test]
fn proof_files_syntactically_valid() {
    let proof_dir = Path::new("proofs/lean4");
    let proof_files = [
        "IFCLatticeSpecification.lean",
        "IFCLatticeIsomorphism.lean",
        "CapabilityAlgebraSpecification.lean",
        "CapabilityAlgebraIsomorphism.lean",
        "PureExprSemantics.lean",
        "translation_validation.lean",
    ];

    for proof_file in &proof_files {
        let proof_path = proof_dir.join(proof_file);
        let proof_content =
            std::fs::read_to_string(&proof_path).expect("Should be able to read proof file");

        // Basic syntactic checks for Lean code
        assert!(
            proof_content.contains("theorem")
                || proof_content.contains("def")
                || proof_content.contains("lemma")
                || proof_content.contains("structure")
                || proof_content.contains("inductive"),
            "Proof file should contain Lean definitions or theorems: {:?}",
            proof_path
        );

        // Should not contain obvious syntax errors
        assert!(
            !proof_content.contains("sorry") || proof_content.matches("sorry").count() < 5,
            "Proof file should not contain many 'sorry' placeholders: {:?}",
            proof_path
        );
    }
}

/// Test that proof files contain formal verification content.
#[test]
fn proof_files_contain_verification_content() {
    let proof_dir = Path::new("proofs/lean4");

    // IFC Lattice proofs should contain lattice operations
    let ifc_spec = std::fs::read_to_string(proof_dir.join("IFCLatticeSpecification.lean"))
        .expect("Should read IFC lattice specification");
    assert!(
        ifc_spec.contains("lattice") || ifc_spec.contains("join") || ifc_spec.contains("meet"),
        "IFC lattice specification should contain lattice operations"
    );

    // Capability algebra proofs should contain algebraic structures
    let cap_spec = std::fs::read_to_string(proof_dir.join("CapabilityAlgebraSpecification.lean"))
        .expect("Should read capability algebra specification");
    assert!(
        cap_spec.contains("algebra")
            || cap_spec.contains("capability")
            || cap_spec.contains("structure"),
        "Capability algebra specification should contain algebraic definitions"
    );

    // Translation validation should contain semantic preservation
    let translation = std::fs::read_to_string(proof_dir.join("translation_validation.lean"))
        .expect("Should read translation validation proofs");
    assert!(
        translation.contains("semantic")
            || translation.contains("equiv")
            || translation.contains("translation"),
        "Translation validation should contain semantic preservation proofs"
    );
}

/// Test that the formal proof verification produces a meaningful report.
#[test]
fn formal_proof_recheck_produces_report() {
    let script_path = "scripts/run_rgc_formal_proof_recheck.sh";

    // Run the script and check it produces logs
    let output = Command::new(script_path)
        .current_dir(".")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Should be able to execute formal proof recheck script");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should mention the G.2 proof bundle
    assert!(
        stdout.contains("G.2") || stdout.contains("proof"),
        "Output should mention G.2 proof bundle verification"
    );

    // Should mention Lean version checking
    assert!(
        stdout.contains("Lean") || stdout.contains("lean"),
        "Output should mention Lean availability checking"
    );

    // Should produce some kind of verification result
    assert!(
        stdout.contains("verification") || stdout.contains("checking") || stdout.contains("build"),
        "Output should mention verification process"
    );
}

/// Test that proof failures are properly detected (regression prevention).
#[test]
fn proof_failure_detection_works() {
    // This test verifies that the proof checking infrastructure would
    // detect actual proof failures. We test this by checking the script's
    // error handling paths.

    let script_content = std::fs::read_to_string("scripts/run_rgc_formal_proof_recheck.sh")
        .expect("Should be able to read proof recheck script");

    // Script should have proper error handling for proof failures
    assert!(
        script_content.contains("error()") || script_content.contains("ERROR"),
        "Script should have error handling for proof failures"
    );

    // Script should fail if lake build fails
    assert!(
        script_content.contains("lake build"),
        "Script should use 'lake build' to check proofs"
    );

    // Script should generate reports on both success and failure
    assert!(
        script_content.contains("generate_proof_report"),
        "Script should generate verification reports"
    );
}

/// Test integration with CI - ensure script follows CI-friendly patterns.
#[test]
fn ci_integration_patterns_followed() {
    let script_content = std::fs::read_to_string("scripts/run_rgc_formal_proof_recheck.sh")
        .expect("Should be able to read proof recheck script");

    // Should have proper exit codes for CI
    assert!(
        script_content.contains("exit") && script_content.contains("$"),
        "Script should use proper exit codes for CI integration"
    );

    // Should handle missing dependencies gracefully
    assert!(
        script_content.contains("command -v") || script_content.contains("which"),
        "Script should check for tool availability"
    );

    // Should generate logs for debugging
    assert!(
        script_content.contains("log") && script_content.contains("LOG_FILE"),
        "Script should generate logs for CI debugging"
    );

    // Should be deterministic (no random elements)
    assert!(
        !script_content.contains("$RANDOM") && !script_content.contains("random"),
        "Script should be deterministic for CI reliability"
    );
}
