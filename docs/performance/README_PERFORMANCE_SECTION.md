## Performance and Security Trade-offs

### Honest Performance Statement

FrankenEngine is a **security-first baseline interpreter** that prioritizes deterministic execution, containment, and governance over raw performance. **FrankenEngine is intentionally 10-100x slower than V8/JavaScriptCore** for compute-intensive workloads.

**📊 Measured Performance Baselines:**
- **Integer arithmetic:** ~50M operations/second
- **Function calls:** ~21M calls/second  
- **Object creation:** ~600K objects/second
- **JSON operations:** ~500 parse/stringify cycles/second

**Why these numbers matter:**
- All measurements are reproducible with artifact bundles in `artifacts/performance_baselines/`
- Performance includes security checks, deterministic constraints, and containment overhead
- JIT compilation tier is planned for future releases to improve performance while preserving safety

### When to Choose FrankenEngine

**✅ FrankenEngine is appropriate for:**
- Extension-heavy agent systems requiring containment
- Applications needing deterministic replay and forensics  
- Security-critical workloads with untrusted code execution
- Governance and compliance scenarios requiring audit trails
- Development where memory safety is more important than speed

**❌ FrankenEngine is NOT appropriate for:**
- High-performance computing applications
- Low-latency real-time systems
- Applications expecting Node.js/V8 performance characteristics
- Workloads where raw speed is the primary concern

### Security-Performance Philosophy

FrankenEngine implements **security and performance as co-equal constraints** - optimizations must preserve deterministic replay, memory safety, and containment properties. This design choice results in measurably slower execution compared to mainstream engines that prioritize performance over security guarantees.

### Performance Documentation

For detailed performance measurements, regression tracking, and benchmark methodologies, see:
- **[Performance Baseline Documentation](docs/PERFORMANCE_BASELINE.md)** - Complete performance measurements and methodology
- **[Benchmark Artifacts](artifacts/performance_baselines/)** - Reproducible performance data with audit trails

**No artifact, no claim.** All performance statements are backed by reproducible benchmarks committed to this repository.