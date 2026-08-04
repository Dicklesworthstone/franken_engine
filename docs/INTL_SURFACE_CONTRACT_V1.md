# Intl Surface Contract V1

> Generated from `docs/intl_surface_contract_v1.json`; do not hand-edit.

## Honest headline

The shipped FrankenEngine JavaScript surface has **no `Intl` global**. `String.prototype.localeCompare` is callable through primitive-method resolution, but it performs deterministic lexicographic comparison and ignores locale/options. Date locale methods and locale-aware casing exist only as internal, unrouted HostCall branches and receive no public or conformance credit.

## Score boundary

- ECMA-262: This contract changes neither numerator nor denominator. Frozen-surface preservation earns zero score points. String.prototype.localeCompare presence/coercion remains an ECMA-262 observable; collation quality never earns ECMA-262 pass credit here.
- ECMA-402: No current row, including the callable localeCompare shortcut, counts as ECMA-402 conformance. A zero denominator is reported as not_measured, never 100%.
- Preservation: Every probe-backed exposed, absent, and internal-non-credit row must retain its exact preservation relation; this is a compatibility score, not a conformance score.

## Frozen surface

| Surface | Exposure | Descriptor observation | ECMA-262 relation | ECMA-402 relation | GA rule |
|---|---|---|---|---|---|
| `date.prototype.to_locale_date_string` | `InternalUnrouted` | `typeof new Date(0).toLocaleDateString` evaluates to `undefined`. | No core score credit because the JavaScript property is absent. | Zero ECMA-402 credit; internal code is explicitly non-credit. | Preserve public absence and non-credit status until the canonical route is intentionally implemented. |
| `date.prototype.to_locale_string` | `InternalUnrouted` | `typeof new Date(0).toLocaleString` evaluates to `undefined`. | No core score credit because the JavaScript property is absent. | Zero ECMA-402 credit; internal code is explicitly non-credit. | Preserve public absence and non-credit status until the canonical route is intentionally implemented. |
| `date.prototype.to_locale_time_string` | `InternalUnrouted` | `typeof new Date(0).toLocaleTimeString` evaluates to `undefined`. | No core score credit because the JavaScript property is absent. | Zero ECMA-402 credit; internal code is explicitly non-credit. | Preserve public absence and non-credit status until the canonical route is intentionally implemented. |
| `date.prototype.to_string_locale_negative_control` | `ExposedNegativeControl` | `new Date(0).toString()` returns `[object Object]`, proving the hidden locale-aware Date HostCall is not the JavaScript route. | Negative control only; contributes no conformance points. | Zero ECMA-402 credit. | Preserve this negative-control observation until Date method routing intentionally changes; then require an explicit migration. |
| `intl.global` | `AbsentProduction` | `typeof Intl` evaluates to `undefined` in a fresh frankenctl/franken-node realm. | No ECMA-262 score delta; ECMA-402 remains a separate excluded profile. | Zero ECMA-402 credit. Absence remains visible in the preservation score. | GA must not claim or accidentally expose a partial Intl namespace without a versioned migration. |
| `number.prototype.to_locale_string` | `AbsentProduction` | `typeof (1234).toLocaleString` evaluates to `undefined`. | No score delta; absence stays visible. | Zero ECMA-402 credit. | GA must not claim NumberFormat or locale number formatting until a complete reviewed route lands. |
| `string.prototype.locale_compare` | `ExposedProduction` | Calling works, but reading `.length` or `.name` fails with `type error: expected object, got function`; no property descriptor is observable. | Method presence and core coercion remain observable; this contract contributes zero score points. | Not ECMA-402 collation conformance. The shortcut receives zero Intl credit. | Preserve exact baseline outputs and environment independence until a signed provider migration intentionally supersedes them. |
| `string.prototype.to_locale_lower_case` | `InternalUnrouted` | `typeof "I".toLocaleLowerCase` evaluates to `undefined`; no descriptor is exposed. | Absent from the frozen JavaScript core surface. | Zero ECMA-402 credit; internal code is explicitly non-credit. | GA may preserve the internal branch, but must preserve public absence unless a reviewed route and provider migration lands. |
| `string.prototype.to_locale_upper_case` | `InternalUnrouted` | `typeof "i".toLocaleUpperCase` evaluates to `undefined`; no descriptor is exposed. | Absent from the frozen JavaScript core surface. | Zero ECMA-402 credit; internal code is explicitly non-credit. | GA may preserve the internal branch, but must preserve public absence unless a reviewed route and provider migration lands. |

## Provider and defaults

- Public provider: `none`
- Default locale: No public Intl default exists. Internal date HostCalls hard-code/fallback to en-US; exposed localeCompare ignores locale arguments.
- Default timezone: No public locale timezone provider exists. Ambient TZ is not consulted by the frozen exposed surface.
- Collation provider: deterministic Rust string ordering over the engine UTF-8 projection; locale/options are ignored
- Ambient environment: LANG, LC_ALL, and TZ must not change the frozen exposed results. Probe profiles C/UTC and hostile locale/TZ values are compared byte-for-byte.

## Reproduction

Run `scripts/bridge/run_bridge_26_intl_e2e.sh --output-root <new-directory>`. The script generates the registry twice, validates bounded source authorities, kills the seeded mutation matrix, and runs each observation through fresh `frankenctl` and `franken-node` processes. The ECMA-402 score remains `not_measured_profile_unselected` until BRIDGE-26.2 selects its denominator.

## Exclusions

- String.prototype.normalize is Unicode-sensitive but not locale-sensitive; it remains in the ECMA-262 core track and is not an Intl preservation row.
- Test262 intl402 profile selection, Unicode/CLDR/tzdb acquisition, normative-optional policy, and full constructors belong to BRIDGE-26.2 through BRIDGE-26.6.
- Internal HostCall reachability from hand-authored IR is not a supported JavaScript or product API and receives no compatibility or conformance credit.
- Node and Bun are reference runtimes only; their broader Intl surfaces do not define FrankenEngine's frozen baseline.
