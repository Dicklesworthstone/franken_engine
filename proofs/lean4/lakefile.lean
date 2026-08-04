import Lake
open Lake DSL

package «frankenengine-ifc-proofs» where

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.7.0"

@[default_target]
lean_lib «IFCLatticeSpecification» where

@[default_target]
lean_lib «IFCLatticeIsomorphism» where

@[default_target]
lean_lib «SmeLabelPropagationEquivalence» where

-- CEI track H.4 (bd-sde5e.8.4): the claim⇄evidence monotonicity/soundness lemma.
-- Pure Lean 4 core (no Mathlib import), so it builds independently of the
-- Mathlib-backed isomorphism libraries above and re-checks in well under a second.
@[default_target]
lean_lib «ClaimEvidenceSoundness» where
