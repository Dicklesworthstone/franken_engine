# FrankenEngine Technical Report Template

## Metadata

- **Report ID**: `FKTR-YYYY-NNN` (e.g., FKTR-2026-001)
- **Title**: [Descriptive title]
- **Authors**: [Author list with affiliations]
- **Date**: YYYY-MM-DD
- **Version**: vX.Y
- **Type**: [Research | Evaluation | Methodology | Failure Analysis]
- **Status**: [Draft | Under Review | Published]
- **DOI/URL**: [If published externally]

## Abstract

[150-250 word summary covering motivation, approach, key findings, and implications]

## 1. Introduction

### 1.1 Problem Statement
[Clear articulation of the research question or engineering challenge]

### 1.2 Motivation
[Why this work matters to the broader security/runtime community]

### 1.3 Contributions
[Numbered list of specific contributions, matching acceptance criteria]

### 1.4 Organization
[Brief roadmap of paper structure]

## 2. Background

### 2.1 Related Work
[Academic and industry context]

### 2.2 FrankenEngine Context
[Relevant system components and design decisions]

## 3. Methodology

### 3.1 Experimental Design
[Research approach, hypotheses, variables]

### 3.2 Implementation
[Technical details, tools, frameworks used]

### 3.3 Evaluation Metrics
[How success/failure is measured]

## 4. Results

### 4.1 Primary Findings
[Core experimental results with data]

### 4.2 Performance Analysis
[Quantitative evaluation with benchmarks]

### 4.3 Security Analysis
[Threat model evaluation, vulnerability assessment]

## 5. Discussion

### 5.1 Implications
[Broader impact on the field]

### 5.2 Limitations
[Honest assessment of constraints and scope]

### 5.3 Threats to Validity
[Potential confounding factors]

## 6. Reproducibility

### 6.1 Artifact Bundle
[Complete reproduction package description]

### 6.2 Hardware Requirements
[Minimum/recommended system specifications]

### 6.3 Software Dependencies
[Exact version requirements, installation steps]

### 6.4 Reproduction Instructions
```bash
# Step-by-step commands to reproduce all results
cd artifact-bundle/
./reproduce_all.sh
```

### 6.5 Expected Outputs
[Description of what successful reproduction should produce]

### 6.6 Validation Checksums
[SHA-256 hashes of key output files for verification]

## 7. Conclusions

### 7.1 Summary
[Restate key contributions and findings]

### 7.2 Future Work
[Research directions opened by this work]

### 7.3 Open Questions
[Unresolved issues for community investigation]

## References

[Academic citations in standard format]

## Appendices

### Appendix A: Detailed Experimental Data
[Raw data tables, extended graphs]

### Appendix B: Implementation Details
[Code listings, configuration files]

### Appendix C: Threat Model
[Formal threat model if applicable]

---

## Template Usage Notes

### Required Sections
All reports MUST include sections 1-6. Section 7 is required for research reports, optional for failure analyses.

### Artifact Bundle Requirements
Every report MUST ship with a complete artifact bundle that includes:
- Source code with exact versions
- Input datasets and test cases
- Build/run scripts with deterministic behavior
- Expected output files with checksums
- Environment specification (OS, compiler versions, etc.)
- README with reproduction instructions

### Reproducibility Standards
Following alien-artifact-coding discipline (Section 5.2):
- Every quantitative claim must have supporting evidence in the artifact bundle
- All experiments must be deterministic with fixed seeds
- All dependencies must be version-pinned
- Reproduction must work in clean environments

### Report Types

#### Research Reports
Focus on novel algorithms, protocols, or system designs. Must include formal evaluation against existing approaches.

#### Evaluation Reports
Systematic assessment of FrankenEngine capabilities versus baselines. Must include external replication validation.

#### Methodology Reports
Documentation of evaluation frameworks, benchmark designs, or analysis techniques for community adoption.

#### Failure Analysis Reports
Post-incident technical analysis documenting root causes, fixes, and lessons learned. Must include honest assessment of failures.

### External Validation
Reports claiming "externally replicated" status must include:
- Independent reproduction by external researchers
- Documentation of replication methodology
- Comparison of original vs. replicated results
- Attribution to external replication teams

### Publication Pathway
1. Draft report following this template
2. Internal technical review
3. Artifact bundle validation
4. External replication (if applicable)
5. Community review period
6. Final publication with DOI