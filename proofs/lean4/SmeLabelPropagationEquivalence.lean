/-
# SME / Label-Propagation Equivalence, V1

This proof captures the shared finite-trace theorem needed by MM.3:
when label propagation and secure multi-execution terminate over the same
finite output trace, their observer-visible outputs are equal.

The theorem is intentionally scoped to the four SME runtime levels implemented
by `secure_multi_execution_kernel.rs`: Public, Internal, Confidential, Secret.
`LabelClass.TopSecret` is outside the SME V1 runtime-copy domain and remains a
counterexample/out-of-scope case until SME grows a TopSecret runtime copy.
-/

import IFCLatticeSpecification

/-- Runtime-copy labels implemented by SecureMultiExecutionKernel. -/
inductive SmeLevel : Type
  | pubLevel : SmeLevel
  | internal : SmeLevel
  | confidential : SmeLevel
  | secret : SmeLevel
deriving DecidableEq, Repr

namespace SmeLevel

/-- Numeric order matching `SecurityLevel` in secure_multi_execution_kernel.rs. -/
def level : SmeLevel -> Nat
  | pubLevel => 0
  | internal => 1
  | confidential => 2
  | secret => 3

/-- SME delivers an output when the observer runtime dominates its label. -/
def dominates (observer outputLabel : SmeLevel) : Bool :=
  decide (outputLabel.level <= observer.level)

/-- Embed the SME V1 domain into the label-propagation lattice. -/
def toLabelClass : SmeLevel -> LabelClass
  | pubLevel => LabelClass.Public
  | internal => LabelClass.Internal
  | confidential => LabelClass.Confidential
  | secret => LabelClass.Secret

/-- Clearance corresponding to an SME observer runtime. -/
def observerClearance : SmeLevel -> Clearance
  | pubLevel => Clearance.NeverSink
  | internal => Clearance.RestrictedSink
  | confidential => Clearance.AuditedSink
  | secret => Clearance.SealedSink

/-- Label-propagation visibility for an SME observer embedded in IFC clearance. -/
def labelPropagationVisible (observer outputLabel : SmeLevel) : Bool :=
  decide ((toLabelClass outputLabel).level <= (observerClearance observer).maxLabelLevel)

/-- Per-output visibility agrees between SME dominance and label propagation. -/
theorem visibility_equivalence (observer outputLabel : SmeLevel) :
    labelPropagationVisible observer outputLabel = dominates observer outputLabel := by
  cases observer <;> cases outputLabel <;> rfl

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
      simp [labelPropagationView, smeView, List.filter, SmeLevel.visibility_equivalence]

def PropagationTerminates
    (_program _input : Nat)
    (observer : SmeLevel)
    (trace output : List Output) : Prop :=
  output = labelPropagationView observer trace

def SmeTerminates
    (_program _input : Nat)
    (observer : SmeLevel)
    (trace output : List Output) : Prop :=
  output = smeView observer trace

def FiniteTraceSemantics : Type :=
  Nat -> Nat -> List Output

def PropagationStrategyTerminates
    (traceOf : FiniteTraceSemantics)
    (program input : Nat)
    (observer : SmeLevel)
    (output : List Output) : Prop :=
  output = labelPropagationView observer (traceOf program input)

def SmeStrategyTerminates
    (traceOf : FiniteTraceSemantics)
    (program input : Nat)
    (observer : SmeLevel)
    (output : List Output) : Prop :=
  output = smeView observer (traceOf program input)

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
