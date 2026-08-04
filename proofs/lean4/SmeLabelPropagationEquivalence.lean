/-
# SME / Label-Propagation Equivalence, V1

This proof captures the shared finite-trace theorem needed by MM.3:
when label propagation and secure multi-execution terminate over the same
finite output trace, their observer-visible outputs are equal.

The theorem is intentionally scoped to the four SME runtime levels implemented
by `secure_multi_execution_kernel.rs`: Public, Internal, Confidential, Secret.
`LabelClass.TopSecret` is outside the SME V1 runtime-copy domain and remains a
counterexample/out-of-scope case until SME grows a TopSecret runtime copy.

Out-of-scope counterexamples documented for MM.3:
- label propagation diverges before producing a finite trace;
- SME diverges before producing a finite trace;
- the two strategies terminate over different traces because the program has
  nondeterministic host effects or a semantic mismatch;
- the program emits TopSecret outputs, which label propagation can represent
  but SME V1 cannot observe with an equivalent runtime level.
-/

import Mathlib.Data.List.Basic
import Mathlib.Tactic
import IFCLatticeSpecification

/-- Runtime-copy labels implemented by SecureMultiExecutionKernel. -/
inductive SmeLevel : Type
  | public : SmeLevel
  | internal : SmeLevel
  | confidential : SmeLevel
  | secret : SmeLevel
deriving DecidableEq, Repr

namespace SmeLevel

/-- Numeric order matching `SecurityLevel` in secure_multi_execution_kernel.rs. -/
def level : SmeLevel -> Nat
  | public => 0
  | internal => 1
  | confidential => 2
  | secret => 3

/-- SME delivers an output when the observer runtime dominates its label. -/
def dominates (observer outputLabel : SmeLevel) : Bool :=
  decide (outputLabel.level <= observer.level)

/-- Embed the SME V1 domain into the label-propagation lattice. -/
def toLabelClass : SmeLevel -> LabelClass
  | public => LabelClass.Public
  | internal => LabelClass.Internal
  | confidential => LabelClass.Confidential
  | secret => LabelClass.Secret

/-- Clearance corresponding to an SME observer runtime. -/
def observerClearance : SmeLevel -> Clearance
  | public => Clearance.NeverSink
  | internal => Clearance.RestrictedSink
  | confidential => Clearance.AuditedSink
  | secret => Clearance.SealedSink

/-- Label-propagation visibility for an SME observer embedded in IFC clearance. -/
def labelPropagationVisible (observer outputLabel : SmeLevel) : Bool :=
  decide ((toLabelClass outputLabel).level <= (observerClearance observer).maxLabelLevel)

/-- Per-output visibility agrees between SME dominance and label propagation. -/
theorem visibility_equivalence (observer outputLabel : SmeLevel) :
    labelPropagationVisible observer outputLabel = dominates observer outputLabel := by
  cases observer <;> cases outputLabel <;>
    simp [labelPropagationVisible, dominates, level, toLabelClass, observerClearance,
      LabelClass.level, Clearance.maxLabelLevel]

end SmeLevel

/-- Abstract output produced by a terminating program trace. -/
structure Output where
  programPoint : Nat
  valueHash : Nat
  label : SmeLevel
deriving DecidableEq, Repr

/-- Label-propagation observer view: retain outputs whose labels can flow. -/
def labelPropagationView (observer : SmeLevel) (trace : List Output) : List Output :=
  trace.filter (fun output => SmeLevel.labelPropagationVisible observer output.label)

/-- SME observer view: retain outputs delivered to the observer runtime copy. -/
def smeView (observer : SmeLevel) (trace : List Output) : List Output :=
  trace.filter (fun output => SmeLevel.dominates observer output.label)

/-- Finite trace views are extensionally equal for every SME observer. -/
theorem finite_trace_view_equivalence (observer : SmeLevel) (trace : List Output) :
    labelPropagationView observer trace = smeView observer trace := by
  induction trace with
  | nil => rfl
  | cons head tail ih =>
      simp [labelPropagationView, smeView, SmeLevel.visibility_equivalence, ih]

/--
`propagation_strategy(p, i)` terminates at observer `L` with `output` when
`output` is the label-propagation view of the shared terminating trace.
-/
def PropagationTerminates
    (_program _input : Nat)
    (observer : SmeLevel)
    (trace output : List Output) : Prop :=
  output = labelPropagationView observer trace

/--
`sme_strategy(p, i)` terminates at observer `L` with `output` when `output` is
the SME view of the shared terminating trace.
-/
def SmeTerminates
    (_program _input : Nat)
    (observer : SmeLevel)
    (trace output : List Output) : Prop :=
  output = smeView observer trace

/--
Deterministic finite-trace semantics for the program fragment where both
strategies terminate. The real runtime supplies the trace; this proof only
relates the two observer projections over that trace.
-/
def FiniteTraceSemantics : Type :=
  Nat -> Nat -> List Output

/--
`propagation_strategy(p, i)` terminates at observer `L` with `output` under a
deterministic finite-trace semantics.
-/
def PropagationStrategyTerminates
    (traceOf : FiniteTraceSemantics)
    (program input : Nat)
    (observer : SmeLevel)
    (output : List Output) : Prop :=
  output = labelPropagationView observer (traceOf program input)

/--
`sme_strategy(p, i)` terminates at observer `L` with `output` under the same
deterministic finite-trace semantics.
-/
def SmeStrategyTerminates
    (traceOf : FiniteTraceSemantics)
    (program input : Nat)
    (observer : SmeLevel)
    (output : List Output) : Prop :=
  output = smeView observer (traceOf program input)

/--
MM.3 equivalence theorem for the terminating shared-trace domain:
for any program, input, and SME observer level, if propagation and SME both
terminate over the same finite trace, their observer outputs are equal.
-/
theorem terminating_shared_trace_output_equivalence
    (program input : Nat)
    (observer : SmeLevel)
    (trace propagationOutput smeOutput : List Output)
    (hPropagation :
      PropagationTerminates program input observer trace propagationOutput)
    (hSme :
      SmeTerminates program input observer trace smeOutput) :
    propagationOutput = smeOutput := by
  unfold PropagationTerminates at hPropagation
  unfold SmeTerminates at hSme
  rw [hPropagation, hSme]
  exact finite_trace_view_equivalence observer trace

/--
MM.3 strategy-shaped theorem:
for any program `p`, input `i`, and SME observer level `L`, if label propagation
terminates with observer output `o_p` and secure multi-execution terminates with
observer output `o_s` over the same deterministic finite-trace semantics, then
`o_p = o_s`.
-/
theorem terminating_strategy_output_equivalence
    (traceOf : FiniteTraceSemantics)
    (program input : Nat)
    (observer : SmeLevel)
    (propagationOutput smeOutput : List Output)
    (hPropagation :
      PropagationStrategyTerminates traceOf program input observer propagationOutput)
    (hSme :
      SmeStrategyTerminates traceOf program input observer smeOutput) :
    propagationOutput = smeOutput := by
  unfold PropagationStrategyTerminates at hPropagation
  unfold SmeStrategyTerminates at hSme
  rw [hPropagation, hSme]
  exact finite_trace_view_equivalence observer (traceOf program input)
