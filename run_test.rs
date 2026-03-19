use frankenengine_engine::entropy_evidence_compressor::*;
fn main() {
    let mut est = EntropyEstimator::new();
    // Do not add any frequencies!
    est.alphabet_size = 1; // pass the first check
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    coder.verify_kraft_inequality().unwrap();
}
