#!/usr/bin/env python3
"""scripts/perf/bootstrap_ci.py — Paired BCa bootstrap confidence intervals.

PERF-ARTIFACT-1.1 (bd-o4cbn.12.1).

Implements the Bias-Corrected and accelerated (BCa) bootstrap of
Efron & Tibshirani (1993), *An Introduction to the Bootstrap*, for paired
benchmark observations. The PERF harness uses this to attach a rigorous
confidence interval to every claimed performance win rather than reporting a
bare point estimate: a "win" only counts when its CI excludes the no-change
value in the favourable direction.

Why BCa over a plain percentile bootstrap
-----------------------------------------
- **Bias correction (z0)** shifts the interval when the bootstrap distribution
  is not median-unbiased about the observed statistic.
- **Acceleration (a)** corrects the skew that arises when the standard error of
  the statistic itself varies with the parameter — typical for ratios /
  percentages such as a relative speedup ``(mean_a - mean_b) / mean_a``.

Both corrections vanish (z0 = a = 0) for a symmetric, location-only statistic,
in which case BCa reduces to the ordinary percentile interval.

Reference: Efron & Tibshirani (1993), Chapter 14; Efron (1987), "Better
Bootstrap Confidence Intervals", JASA 82(397):171-185.

Reproducibility
---------------
All resampling draws come from ``numpy.random.default_rng(seed)`` with a fixed
default seed (42), so a given (data, seed, n_resamples) triple yields a
bit-identical interval on every run.

Usage
-----
    # Compare two Criterion sample dumps (baseline A vs candidate B):
    bootstrap_ci.py compare --baseline a/sample.json --candidate b/sample.json

    # Compare two raw newline/JSON sample files of paired observations:
    bootstrap_ci.py compare --baseline a.txt --candidate b.txt --statistic relative_speedup

    # Run the self-test against Efron's law-school data:
    bootstrap_ci.py self-test

The module is also importable: ``from bootstrap_ci import bca_ci``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Callable, Sequence

import numpy as np
from scipy import stats

DEFAULT_SEED = 42
DEFAULT_RESAMPLES = 10_000
DEFAULT_CONF = 0.95

StatisticFn = Callable[[np.ndarray, np.ndarray], float]


# --------------------------------------------------------------------------- #
# Core BCa estimator
# --------------------------------------------------------------------------- #
def bca_ci(
    samples_a: Sequence[float],
    samples_b: Sequence[float],
    statistic_fn: StatisticFn,
    n_resamples: int = DEFAULT_RESAMPLES,
    conf: float = DEFAULT_CONF,
    seed: int = DEFAULT_SEED,
) -> tuple[float, float, float]:
    """Paired BCa confidence interval on ``statistic_fn(a, b)``.

    Args:
        samples_a, samples_b: length-N arrays of *paired* observations. The
            i-th entry of each must come from the same experimental unit
            (e.g. the i-th Criterion sample of the baseline vs the candidate),
            because BCa resamples the pair index jointly.
        statistic_fn: maps ``(a, b) -> scalar``. Examples: the relative speedup
            ``(mean(a) - mean(b)) / mean(a)`` or a paired correlation.
        n_resamples: number of bootstrap resamples (B).
        conf: two-sided confidence level, e.g. 0.95.
        seed: fixed RNG seed for reproducibility.

    Returns:
        ``(point_estimate, ci_low, ci_high)``.

    Raises:
        ValueError: on mismatched / too-short inputs or a degenerate confidence
            level.
    """
    a_arr = np.asarray(samples_a, dtype=float)
    b_arr = np.asarray(samples_b, dtype=float)
    if a_arr.ndim != 1 or b_arr.ndim != 1:
        raise ValueError("samples_a and samples_b must be 1-D")
    if a_arr.shape != b_arr.shape:
        raise ValueError(
            f"paired BCa requires equal-length samples; got {a_arr.shape[0]} vs {b_arr.shape[0]}"
        )
    n = a_arr.shape[0]
    if n < 2:
        raise ValueError("need at least 2 paired observations")
    if not 0.0 < conf < 1.0:
        raise ValueError("conf must lie strictly in (0, 1)")
    if n_resamples < 1:
        raise ValueError("n_resamples must be >= 1")

    theta_hat = float(statistic_fn(a_arr, b_arr))

    # --- Bootstrap distribution (jointly resampled index, fixed seed) -------- #
    rng = np.random.default_rng(seed)
    boot = np.empty(n_resamples, dtype=float)
    for i in range(n_resamples):
        idx = rng.integers(0, n, n)
        boot[i] = statistic_fn(a_arr[idx], b_arr[idx])

    # --- Bias-correction z0 -------------------------------------------------- #
    # Proportion of bootstrap replicates below the observed statistic. Clamp away
    # from {0, 1} so norm.ppf stays finite when the statistic is at an extreme.
    prop = float(np.mean(boot < theta_hat))
    eps = 1.0 / (n_resamples + 1.0)
    prop = min(max(prop, eps), 1.0 - eps)
    z0 = float(stats.norm.ppf(prop))

    # --- Acceleration a (jackknife, deterministic) --------------------------- #
    jack = np.empty(n, dtype=float)
    for i in range(n):
        jack[i] = statistic_fn(np.delete(a_arr, i), np.delete(b_arr, i))
    jack_mean = jack.mean()
    deltas = jack_mean - jack
    a_num = float((deltas**3).sum())
    a_den = 6.0 * float((deltas**2).sum()) ** 1.5
    a = a_num / a_den if a_den != 0.0 else 0.0

    # --- BCa-adjusted percentiles ------------------------------------------- #
    alpha = (1.0 - conf) / 2.0
    z_lo = float(stats.norm.ppf(alpha))
    z_hi = float(stats.norm.ppf(1.0 - alpha))

    def _adjust(z: float) -> float:
        denom = 1.0 - a * (z0 + z)
        # Guard against the acceleration pushing the denominator through zero.
        if denom == 0.0:
            denom = math.copysign(1e-12, denom or 1.0)
        p = float(stats.norm.cdf(z0 + (z0 + z) / denom))
        return min(max(p, 0.0), 1.0)

    p_lo = _adjust(z_lo)
    p_hi = _adjust(z_hi)
    ci_low = float(np.quantile(boot, p_lo))
    ci_high = float(np.quantile(boot, p_hi))
    return theta_hat, ci_low, ci_high


# --------------------------------------------------------------------------- #
# Named statistics for benchmark comparison
# --------------------------------------------------------------------------- #
def relative_speedup(a: np.ndarray, b: np.ndarray) -> float:
    """Fractional speedup of candidate ``b`` over baseline ``a`` for timings.

    Positive means the candidate is faster (lower time). For a 10% speedup this
    returns 0.10.
    """
    mean_a = float(np.mean(a))
    if mean_a == 0.0:
        raise ValueError("baseline mean is zero; relative_speedup undefined")
    return (mean_a - float(np.mean(b))) / mean_a


def relative_change(a: np.ndarray, b: np.ndarray) -> float:
    """Signed relative change ``(mean(b) - mean(a)) / mean(a)`` (matches the
    bead's worked example). For timings, negative means the candidate is
    faster."""
    mean_a = float(np.mean(a))
    if mean_a == 0.0:
        raise ValueError("baseline mean is zero; relative_change undefined")
    return (float(np.mean(b)) - mean_a) / mean_a


def mean_difference(a: np.ndarray, b: np.ndarray) -> float:
    """Absolute difference of means, ``mean(b) - mean(a)`` (same units as
    input)."""
    return float(np.mean(b)) - float(np.mean(a))


STATISTICS: dict[str, StatisticFn] = {
    "relative_speedup": relative_speedup,
    "relative_change": relative_change,
    "mean_difference": mean_difference,
}


# --------------------------------------------------------------------------- #
# Sample loaders
# --------------------------------------------------------------------------- #
def load_criterion_samples(path: str) -> np.ndarray:
    """Load per-iteration timings (nanoseconds) from a Criterion ``sample.json``.

    Criterion records, per sample, the total ``time`` for ``iters`` iterations;
    the per-iteration estimate is ``time / iters``. Returns one value per
    Criterion sample so the array can be paired index-wise against another run
    of the same benchmark (Criterion uses a fixed sample_size per benchmark).
    """
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    times = doc.get("times")
    iters = doc.get("iters")
    if times is None or iters is None:
        raise ValueError(
            f"{path}: not a Criterion sample.json (missing 'times'/'iters')"
        )
    t = np.asarray(times, dtype=float)
    n = np.asarray(iters, dtype=float)
    if t.shape != n.shape:
        raise ValueError(f"{path}: 'times' and 'iters' length mismatch")
    with np.errstate(divide="raise", invalid="raise"):
        return t / n


def load_plain_samples(path: str) -> np.ndarray:
    """Load samples from a plain file: a JSON array of numbers, or one number
    per line (``#`` comments and blanks ignored)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        return np.asarray(json.loads(stripped), dtype=float)
    vals = [
        float(line)
        for raw in text.splitlines()
        if (line := raw.strip()) and not line.startswith("#")
    ]
    return np.asarray(vals, dtype=float)


def _load(path: str) -> np.ndarray:
    """Dispatch loader by file shape: Criterion JSON if it has times/iters,
    else plain."""
    if path.endswith(".json"):
        try:
            return load_criterion_samples(path)
        except ValueError:
            pass
    return load_plain_samples(path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _verdict(statistic: str, ci_low: float, ci_high: float) -> str:
    """A win is significant iff the whole CI sits on the favourable side of the
    no-change value (0)."""
    favourable_positive = statistic in ("relative_speedup",)
    favourable_negative = statistic in ("relative_change", "mean_difference")
    if favourable_positive:
        if ci_low > 0.0:
            return "SIGNIFICANT_WIN"
        if ci_high < 0.0:
            return "SIGNIFICANT_REGRESSION"
    elif favourable_negative:
        if ci_high < 0.0:
            return "SIGNIFICANT_WIN"
        if ci_low > 0.0:
            return "SIGNIFICANT_REGRESSION"
    return "INCONCLUSIVE"


def _cmd_compare(args: argparse.Namespace) -> int:
    a = _load(args.baseline)
    b = _load(args.candidate)
    stat_fn = STATISTICS[args.statistic]
    point, lo, hi = bca_ci(
        a, b, stat_fn,
        n_resamples=args.resamples,
        conf=args.conf,
        seed=args.seed,
    )
    verdict = _verdict(args.statistic, lo, hi)
    result = {
        "statistic": args.statistic,
        "baseline": args.baseline,
        "candidate": args.candidate,
        "n_baseline": int(a.shape[0]),
        "n_candidate": int(b.shape[0]),
        "n_resamples": args.resamples,
        "confidence_level": args.conf,
        "seed": args.seed,
        "point_estimate": point,
        "ci_low": lo,
        "ci_high": hi,
        "verdict": verdict,
    }
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        pct = args.conf * 100.0
        print(f"statistic       : {args.statistic}")
        print(f"point estimate  : {point:+.6f}")
        print(f"{pct:.0f}% BCa CI    : [{lo:+.6f}, {hi:+.6f}]")
        print(f"resamples / seed: {args.resamples} / {args.seed}")
        print(f"verdict         : {verdict}")
    return 0


def _cmd_self_test(_args: argparse.Namespace) -> int:
    import unittest

    suite = unittest.TestLoader().loadTestsFromTestCase(BcaSelfTest)
    runner = unittest.TextTestRunner(verbosity=2)
    return 0 if runner.run(suite).wasSuccessful() else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    cmp_p = sub.add_parser("compare", help="paired BCa CI for baseline vs candidate samples")
    cmp_p.add_argument("--baseline", required=True, help="baseline sample file (Criterion sample.json or plain)")
    cmp_p.add_argument("--candidate", required=True, help="candidate sample file (same shape as baseline)")
    cmp_p.add_argument("--statistic", choices=sorted(STATISTICS), default="relative_speedup")
    cmp_p.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    cmp_p.add_argument("--conf", type=float, default=DEFAULT_CONF)
    cmp_p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    cmp_p.add_argument("--format", choices=("json", "text"), default="json")
    cmp_p.set_defaults(func=_cmd_compare)

    st_p = sub.add_parser("self-test", help="run the Efron law-school BCa unit test")
    st_p.set_defaults(func=_cmd_self_test)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


# --------------------------------------------------------------------------- #
# Unit test — Efron's law-school data (also runnable via `python3 -m unittest`)
# --------------------------------------------------------------------------- #
# Efron & Tibshirani (1993), Table 3.1: LSAT / GPA for N=15 law schools.
_LAW_SCHOOL_LSAT = (576, 635, 558, 578, 666, 580, 555, 661, 651, 605, 653, 575, 545, 572, 594)
_LAW_SCHOOL_GPA = (3.39, 3.30, 2.81, 3.03, 3.44, 3.07, 3.00, 3.43, 3.36, 3.13, 3.12, 2.74, 2.76, 2.88, 2.96)


def _pearson_corr(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.corrcoef(a, b)[0, 1])


import unittest  # noqa: E402  (kept at bottom so the CLI imports stay light)


class BcaSelfTest(unittest.TestCase):
    """Validate the BCa estimator on Efron's canonical law-school correlation.

    Efron & Tibshirani (1993), Table 14.2, report a BCa 90% interval of roughly
    (0.43, 0.92) for the LSAT/GPA correlation (point estimate 0.776). We pin
    three things: (1) the deterministic point estimate, (2) agreement with the
    published interval, and (3) agreement with SciPy's independent BCa
    implementation, plus reproducibility under the fixed seed.
    """

    LSAT = np.array(_LAW_SCHOOL_LSAT, dtype=float)
    GPA = np.array(_LAW_SCHOOL_GPA, dtype=float)

    def test_point_estimate_matches_published(self) -> None:
        point, _, _ = bca_ci(self.LSAT, self.GPA, _pearson_corr, n_resamples=20_000, conf=0.90)
        self.assertAlmostEqual(point, 0.776374, places=5)

    def test_ci_brackets_point_and_matches_efron(self) -> None:
        point, lo, hi = bca_ci(self.LSAT, self.GPA, _pearson_corr, n_resamples=20_000, conf=0.90)
        # CI must bracket the observed statistic.
        self.assertLess(lo, point)
        self.assertGreater(hi, point)
        # Efron & Tibshirani (1993) Table 14.2: BCa 90% ~= (0.43, 0.92).
        self.assertAlmostEqual(lo, 0.43, delta=0.05)
        self.assertAlmostEqual(hi, 0.92, delta=0.05)

    def test_matches_scipy_bca(self) -> None:
        _, lo, hi = bca_ci(self.LSAT, self.GPA, _pearson_corr, n_resamples=20_000, conf=0.90)
        ref = stats.bootstrap(
            (self.LSAT, self.GPA), _pearson_corr, paired=True, method="BCa",
            confidence_level=0.90, n_resamples=20_000,
            random_state=np.random.default_rng(DEFAULT_SEED),
        )
        self.assertAlmostEqual(lo, ref.confidence_interval.low, delta=0.02)
        self.assertAlmostEqual(hi, ref.confidence_interval.high, delta=0.02)

    def test_reproducible_under_fixed_seed(self) -> None:
        r1 = bca_ci(self.LSAT, self.GPA, _pearson_corr, n_resamples=5_000)
        r2 = bca_ci(self.LSAT, self.GPA, _pearson_corr, n_resamples=5_000)
        self.assertEqual(r1, r2)

    def test_relative_speedup_significance(self) -> None:
        # Candidate is ~20% faster with low noise -> significant win, CI > 0.
        rng = np.random.default_rng(7)
        base = rng.normal(100.0, 2.0, 64)
        cand = rng.normal(80.0, 2.0, 64)
        point, lo, hi = bca_ci(base, cand, relative_speedup, n_resamples=5_000)
        self.assertGreater(point, 0.0)
        self.assertGreater(lo, 0.0)
        self.assertEqual(_verdict("relative_speedup", lo, hi), "SIGNIFICANT_WIN")

    def test_no_difference_is_inconclusive(self) -> None:
        # Same distribution both sides -> CI should straddle 0.
        rng = np.random.default_rng(11)
        base = rng.normal(100.0, 3.0, 80)
        cand = rng.normal(100.0, 3.0, 80)
        _, lo, hi = bca_ci(base, cand, relative_speedup, n_resamples=5_000)
        self.assertEqual(_verdict("relative_speedup", lo, hi), "INCONCLUSIVE")

    def test_rejects_mismatched_lengths(self) -> None:
        with self.assertRaises(ValueError):
            bca_ci([1.0, 2.0, 3.0], [1.0, 2.0], mean_difference)


if __name__ == "__main__":
    sys.exit(main())
