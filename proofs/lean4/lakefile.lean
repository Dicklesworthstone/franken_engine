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
