import Lake
open Lake DSL

package «frankenengine-ifc-proofs» where
  version := v!"0.1.0"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git"

@[default_target]
lean_lib «IFCLatticeSpecification» where

@[default_target]
lean_lib «IFCLatticeIsomorphism» where