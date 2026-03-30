use frankenengine_engine::ambient_authority::{AuditConfig, ExemptionRegistry, SourceAuditor};

#[test]
fn test_bypass() {
    let config = AuditConfig::standard();
    let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
    
    let source = r#"
        let bypass = '"';
        std::fs::read("secrets");
        let close_bypass = '"';
    "#;
    
    let findings = auditor.audit_source("test_mod", "test.rs", source);
    println!("Findings: {:#?}", findings);
    assert_eq!(findings.len(), 2, "Should find the forbidden call");
}