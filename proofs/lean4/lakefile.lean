import Lake
open Lake DSL

-- Pure Lean 4 core proof suite (no external mathlib git fetch required;
-- keeps verification fast, offline-reproducible, and immune to mathlib drift).
package «frankenengine-ifc-proofs» where
  version := v!"0.2.0"

@[default_target]
lean_lib «IFCLatticeSpecification» where

@[default_target]
lean_lib «IFCLatticeIsomorphism» where

@[default_target]
lean_lib «ClaimEvidenceSoundness» where

@[default_target]
lean_lib «SmeLabelPropagationEquivalence» where

@[default_target]
lean_lib «CapabilityAlgebraSpecification» where

@[default_target]
lean_lib «CapabilityAlgebraIsomorphism» where

@[default_target]
lean_lib «PureExprSemantics» where

@[default_target]
lean_lib «translation_validation» where
