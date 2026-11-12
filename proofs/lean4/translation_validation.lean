/-
# Translation Validation Framework for FrankenEngine

Mechanized translation validation framework for FrankenEngine's multi-level IR
transformation pipeline (`IR0 → IR1 → IR2 → IR3`), proven in pure Lean 4 core
with complete kernel-checked proofs, coherent scope-environment witnesses, register non-interference
lemmas, phi-join equivalence, and a total verified compiler `generateWitness`.

Related: bd-cixqu.7.6, bd-cixqu.7.8, FE-CLAIM-017, FE-CLAIM-018, bd-rc-2026-11-11-epic-g2vrp.10
-/

import PureExprSemantics
import IFCLatticeSpecification

-- =============================================================================
-- IR Level Representations
-- =============================================================================

inductive BinaryOperator : Type
  | Add | Subtract | Multiply | Divide | Remainder | Exponentiate
  | Equal | NotEqual | StrictEqual | StrictNotEqual
  | LessThan | LessThanOrEqual | GreaterThan | GreaterThanOrEqual
  | LogicalAnd | LogicalOr | NullishCoalescing
  | BitwiseAnd | BitwiseOr | BitwiseXor
  | LeftShift | RightShift | UnsignedRightShift
deriving DecidableEq, Repr

inductive UnaryOperator : Type
  | Negate | UnaryPlus | LogicalNot | BitwiseNot | Typeof | Void
deriving DecidableEq, Repr

inductive IR0Expr : Type
  | literal       : JSValue → IR0Expr
  | identifier    : String → IR0Expr
  | binary        : BinaryOperator → IR0Expr → IR0Expr → IR0Expr
  | unary         : UnaryOperator → IR0Expr → IR0Expr
  | parenthesized : IR0Expr → IR0Expr
deriving DecidableEq, Repr

inductive IR1Expr : Type
  | literal : JSValue → IR1Expr
  | binding : Nat → IR1Expr
  | binary  : BinaryOperator → IR1Expr → IR1Expr → IR1Expr
  | unary   : UnaryOperator → IR1Expr → IR1Expr
deriving DecidableEq, Repr

structure IR2Expr : Type where
  expr  : IR1Expr
  label : LabelClass
deriving DecidableEq, Repr

inductive IR3Instruction : Type
  | LoadLiteral : Nat → JSValue → IR3Instruction
  | LoadBinding : Nat → Nat → IR3Instruction
  | BinaryOp    : Nat → BinaryOperator → Nat → Nat → IR3Instruction
  | UnaryOp     : Nat → UnaryOperator → Nat → IR3Instruction
deriving DecidableEq, Repr

abbrev IR3Program := List IR3Instruction

-- =============================================================================
-- Operator Bridge & IR Evaluation Semantics
-- =============================================================================

def binaryOpToPure : BinaryOperator → PureBinaryOp
  | .Add                => .add
  | .Subtract           => .subtract
  | .Multiply           => .multiply
  | .Divide             => .divide
  | .Remainder          => .remainder
  | .Exponentiate       => .exponentiate
  | .Equal              => .equal
  | .NotEqual           => .notEqual
  | .StrictEqual        => .strictEqual
  | .StrictNotEqual     => .strictNotEqual
  | .LessThan           => .lessThan
  | .LessThanOrEqual    => .lessThanEqual
  | .GreaterThan        => .greaterThan
  | .GreaterThanOrEqual => .greaterThanEqual
  | .LogicalAnd         => .logicalAnd
  | .LogicalOr          => .logicalOr
  | .NullishCoalescing  => .nullishCoalescing
  | .BitwiseAnd         => .bitwiseAnd
  | .BitwiseOr          => .bitwiseOr
  | .BitwiseXor         => .bitwiseXor
  | .LeftShift          => .leftShift
  | .RightShift         => .rightShift
  | .UnsignedRightShift => .unsignedRightShift

def unaryOpToPure : UnaryOperator → PureUnaryOp
  | .Negate     => .negate
  | .UnaryPlus  => .unaryPlus
  | .LogicalNot => .logicalNot
  | .BitwiseNot => .bitwiseNot
  | .Typeof     => .typeof
  | .Void       => .void

def evalBinaryOp (op : BinaryOperator) (left right : JSValue) : JSValue :=
  PureBinaryOp.eval (binaryOpToPure op) left right

def evalUnaryOp (op : UnaryOperator) (operand : JSValue) : JSValue :=
  PureUnaryOp.eval (unaryOpToPure op) operand

namespace IR0Expr

def Env := String → Option JSValue

def eval (env : Env) : IR0Expr → Option JSValue
  | literal v          => some v
  | identifier name    => env name
  | binary op l r      =>
    match eval env l, eval env r with
    | some lv, some rv => some (evalBinaryOp op lv rv)
    | _, _             => none
  | unary op operand   =>
    match eval env operand with
    | some v => some (evalUnaryOp op v)
    | none   => none
  | parenthesized e    => eval env e

end IR0Expr

namespace IR1Expr

def Env := Nat → Option JSValue

def eval (env : Env) : IR1Expr → Option JSValue
  | literal v        => some v
  | binding id       => env id
  | binary op l r    =>
    match eval env l, eval env r with
    | some lv, some rv => some (evalBinaryOp op lv rv)
    | _, _             => none
  | unary op operand =>
    match eval env operand with
    | some v => some (evalUnaryOp op v)
    | none   => none

end IR1Expr

namespace IR2Expr

def eval (env : IR1Expr.Env) (e : IR2Expr) : Option JSValue :=
  IR1Expr.eval env e.expr

end IR2Expr

namespace IR3Program

abbrev RegisterFile := Nat → Option JSValue

def dstReg : IR3Instruction → Nat
  | .LoadLiteral reg _   => reg
  | .LoadBinding reg _   => reg
  | .BinaryOp reg _ _ _  => reg
  | .UnaryOp reg _ _     => reg

def execInstruction (env : IR1Expr.Env) (regs : RegisterFile) : IR3Instruction → RegisterFile
  | .LoadLiteral reg value =>
    fun r => if r = reg then some value else regs r
  | .LoadBinding reg bindingId =>
    fun r => if r = reg then env bindingId else regs r
  | .BinaryOp reg op leftReg rightReg =>
    fun r => if r = reg then
      match regs leftReg, regs rightReg with
      | some leftVal, some rightVal => some (evalBinaryOp op leftVal rightVal)
      | _, _ => none
    else regs r
  | .UnaryOp reg op operandReg =>
    fun r => if r = reg then
      match regs operandReg with
      | some operandVal => some (evalUnaryOp op operandVal)
      | _ => none
    else regs r

def execList (env : IR1Expr.Env) (regs : RegisterFile) (prog : IR3Program) : RegisterFile :=
  prog.foldl (execInstruction env) regs

def eval (env : IR1Expr.Env) (program : IR3Program) (resultReg : Nat) : Option JSValue :=
  execList env (fun _ => none) program resultReg

theorem execList_append (env : IR1Expr.Env) (regs : RegisterFile) (p1 p2 : IR3Program) :
    execList env regs (p1 ++ p2) = execList env (execList env regs p1) p2 := by
  simp [execList, List.foldl_append]

theorem execInstruction_preserves_ne (env : IR1Expr.Env) (regs : RegisterFile)
    (instr : IR3Instruction) (r : Nat) (hne : r ≠ dstReg instr) :
    execInstruction env regs instr r = regs r := by
  cases instr <;> simp [execInstruction, dstReg] at hne ⊢ <;> simp [hne]

theorem execList_preserves_below (env : IR1Expr.Env) (regs : RegisterFile)
    (prog : IR3Program) (r : Nat)
    (h_unused : ∀ instr ∈ prog, r < dstReg instr) :
    execList env regs prog r = regs r := by
  induction prog generalizing regs with
  | nil => rfl
  | cons hd tl ih =>
    change execList env (execInstruction env regs hd) tl r = regs r
    have hlt : r < dstReg hd := h_unused hd (by simp)
    have hne : r ≠ dstReg hd := Nat.ne_of_lt hlt
    have htl : ∀ instr ∈ tl, r < dstReg instr :=
      fun instr hm => h_unused instr (List.mem_cons_of_mem hd hm)
    rw [ih (execInstruction env regs hd) htl, execInstruction_preserves_ne env regs hd r hne]

end IR3Program

-- =============================================================================
-- Coherent Scope Environment & Translation Witnesses
-- =============================================================================

/-- Scope-resolution coherence: every source identifier `name` resolves in `env1`
    at slot `scope_map name` to the same value as `env0 name`. -/
def ScopeEnvCoherent (scope_map : String → Nat) (env0 : IR0Expr.Env) (env1 : IR1Expr.Env) : Prop :=
  ∀ name : String, env0 name = env1 (scope_map name)

structure IR0ToIR1Witness where
  ir0_expr  : IR0Expr
  ir1_expr  : IR1Expr
  scope_map : String → Nat
  equivalence : ∀ (env0 : IR0Expr.Env) (env1 : IR1Expr.Env),
    ScopeEnvCoherent scope_map env0 env1 →
    IR0Expr.eval env0 ir0_expr = IR1Expr.eval env1 ir1_expr

structure IR1ToIR2Witness where
  ir1_expr : IR1Expr
  ir2_expr : IR2Expr
  equivalence : ∀ (env : IR1Expr.Env),
    IR1Expr.eval env ir1_expr = IR2Expr.eval env ir2_expr

structure IR2ToIR3Witness where
  ir2_expr        : IR2Expr
  ir3_program     : IR3Program
  result_register : Nat
  equivalence : ∀ (env : IR1Expr.Env),
    IR2Expr.eval env ir2_expr = IR3Program.eval env ir3_program result_register

structure PipelineValidationWitness where
  ir0_expr        : IR0Expr
  ir1_expr        : IR1Expr
  ir2_expr        : IR2Expr
  ir3_program     : IR3Program
  result_register : Nat
  ir0_to_ir1      : IR0ToIR1Witness
  ir1_to_ir2      : IR1ToIR2Witness
  ir2_to_ir3      : IR2ToIR3Witness
  ir0_matches     : ir0_to_ir1.ir0_expr = ir0_expr
  ir1_matches     : ir0_to_ir1.ir1_expr = ir1_expr ∧ ir1_to_ir2.ir1_expr = ir1_expr
  ir2_matches     : ir1_to_ir2.ir2_expr = ir2_expr ∧ ir2_to_ir3.ir2_expr = ir2_expr
  ir3_matches     : ir2_to_ir3.ir3_program = ir3_program ∧ ir2_to_ir3.result_register = result_register

/-- Main theorem: Pipeline preserves expression semantics end-to-end across all coherent environments. -/
theorem pipeline_correctness (witness : PipelineValidationWitness) :
    ∀ (env0 : IR0Expr.Env) (env1 : IR1Expr.Env),
      ScopeEnvCoherent witness.ir0_to_ir1.scope_map env0 env1 →
      IR0Expr.eval env0 witness.ir0_expr =
      IR3Program.eval env1 witness.ir3_program witness.result_register := by
  intro env0 env1 h_coh
  calc
    IR0Expr.eval env0 witness.ir0_expr
        = IR0Expr.eval env0 witness.ir0_to_ir1.ir0_expr := by rw [witness.ir0_matches]
    _   = IR1Expr.eval env1 witness.ir0_to_ir1.ir1_expr := witness.ir0_to_ir1.equivalence env0 env1 h_coh
    _   = IR1Expr.eval env1 witness.ir1_expr            := by rw [witness.ir1_matches.1]
    _   = IR1Expr.eval env1 witness.ir1_to_ir2.ir1_expr := by rw [← witness.ir1_matches.2]
    _   = IR2Expr.eval env1 witness.ir1_to_ir2.ir2_expr := witness.ir1_to_ir2.equivalence env1
    _   = IR2Expr.eval env1 witness.ir2_expr            := by rw [witness.ir2_matches.1]
    _   = IR2Expr.eval env1 witness.ir2_to_ir3.ir2_expr := by rw [← witness.ir2_matches.2]
    _   = IR3Program.eval env1 witness.ir2_to_ir3.ir3_program witness.ir2_to_ir3.result_register :=
          witness.ir2_to_ir3.equivalence env1
    _   = IR3Program.eval env1 witness.ir3_program witness.result_register := by
          rw [witness.ir3_matches.1, witness.ir3_matches.2]

/-- Boolean structural coherence check over a `PipelineValidationWitness`. -/
def verifyWitness (witness : PipelineValidationWitness) : Bool :=
  decide (witness.ir0_to_ir1.ir0_expr = witness.ir0_expr) &&
  decide (witness.ir0_to_ir1.ir1_expr = witness.ir1_expr) &&
  decide (witness.ir1_to_ir2.ir1_expr = witness.ir1_expr) &&
  decide (witness.ir1_to_ir2.ir2_expr = witness.ir2_expr) &&
  decide (witness.ir2_to_ir3.ir2_expr = witness.ir2_expr) &&
  decide (witness.ir2_to_ir3.ir3_program = witness.ir3_program) &&
  decide (witness.ir2_to_ir3.result_register = witness.result_register)

theorem verifyWitness_always_true (witness : PipelineValidationWitness) :
    verifyWitness witness = true := by
  simp [verifyWitness, witness.ir0_matches, witness.ir1_matches.1, witness.ir1_matches.2,
        witness.ir2_matches.1, witness.ir2_matches.2, witness.ir3_matches.1, witness.ir3_matches.2]

-- =============================================================================
-- Verified Lowering Compiler (`generateWitness`)
-- =============================================================================

def lowerIR0ToIR1 (scope_map : String → Nat) : IR0Expr → IR1Expr
  | .literal v        => .literal v
  | .identifier name  => .binding (scope_map name)
  | .binary op l r    => .binary op (lowerIR0ToIR1 scope_map l) (lowerIR0ToIR1 scope_map r)
  | .unary op operand => .unary op (lowerIR0ToIR1 scope_map operand)
  | .parenthesized e  => lowerIR0ToIR1 scope_map e

theorem lowerIR0ToIR1_correct (scope_map : String → Nat) (e : IR0Expr)
    (env0 : IR0Expr.Env) (env1 : IR1Expr.Env)
    (h_coh : ScopeEnvCoherent scope_map env0 env1) :
    IR0Expr.eval env0 e = IR1Expr.eval env1 (lowerIR0ToIR1 scope_map e) := by
  induction e with
  | literal v => rfl
  | identifier name => exact h_coh name
  | binary op l r ihl ihr =>
    simp [IR0Expr.eval, lowerIR0ToIR1, IR1Expr.eval, ihl, ihr]
  | unary op operand ih =>
    simp [IR0Expr.eval, lowerIR0ToIR1, IR1Expr.eval, ih]
  | parenthesized inner ih =>
    simpa [IR0Expr.eval, lowerIR0ToIR1] using ih

/-- Compile `IR1Expr` starting at fresh register `base`, returning `(prog, outReg, nextFreeReg)`. -/
def compileIR1 (e : IR1Expr) (base : Nat) : IR3Program × Nat × Nat :=
  match e with
  | .literal v =>
    ([.LoadLiteral base v], base, base + 1)
  | .binding id =>
    ([.LoadBinding base id], base, base + 1)
  | .unary op operand =>
    let (p1, r1, next1) := compileIR1 operand base
    (p1 ++ [.UnaryOp next1 op r1], next1, next1 + 1)
  | .binary op l r =>
    let (pl, rl, next1) := compileIR1 l base
    let (pr, rr, next2) := compileIR1 r next1
    (pl ++ pr ++ [.BinaryOp next2 op rl rr], next2, next2 + 1)

theorem compileIR1_bounds (e : IR1Expr) (base : Nat) :
    let (prog, outReg, nextReg) := compileIR1 e base
    base ≤ outReg ∧ outReg < nextReg ∧
    (∀ instr ∈ prog, base ≤ IR3Program.dstReg instr ∧ IR3Program.dstReg instr < nextReg) := by
  induction e generalizing base with
  | literal v =>
    simp [compileIR1, IR3Program.dstReg]
  | binding id =>
    simp [compileIR1, IR3Program.dstReg]
  | unary op operand ih =>
    have ih1 := ih base
    rcases h1 : compileIR1 operand base with ⟨p1, r1, next1⟩
    rw [h1] at ih1
    rcases ih1 with ⟨hb_r1, hr1_n1, hp1⟩
    simp only [compileIR1, h1]
    refine ⟨by omega, by omega, ?_⟩
    intro instr hm
    rw [List.mem_append] at hm
    rcases hm with hm | hm
    · obtain ⟨hlo, hhi⟩ := hp1 instr hm
      exact ⟨hlo, by omega⟩
    · simp only [List.mem_singleton] at hm
      subst hm
      simp [IR3Program.dstReg]; omega
  | binary op l r ihl ihr =>
    have ihl1 := ihl base
    rcases hl : compileIR1 l base with ⟨pl, rl, next1⟩
    rw [hl] at ihl1
    rcases ihl1 with ⟨hb_rl, hrl_n1, hpl⟩
    have ihr1 := ihr next1
    rcases hr : compileIR1 r next1 with ⟨pr, rr, next2⟩
    rw [hr] at ihr1
    rcases ihr1 with ⟨hn1_rr, hrr_n2, hpr⟩
    simp only [compileIR1, hl, hr]
    refine ⟨by omega, by omega, ?_⟩
    intro instr hm
    rw [List.mem_append, List.mem_append] at hm
    rcases hm with (hm | hm) | hm
    · obtain ⟨hlo, hhi⟩ := hpl instr hm
      exact ⟨hlo, by omega⟩
    · obtain ⟨hlo, hhi⟩ := hpr instr hm
      exact ⟨by omega, by omega⟩
    · simp only [List.mem_singleton] at hm
      subst hm
      simp [IR3Program.dstReg]; omega

theorem compileIR1_correct (e : IR1Expr) (base : Nat)
    (env : IR1Expr.Env) (regs : IR3Program.RegisterFile) :
    let (prog, outReg, _) := compileIR1 e base
    IR3Program.execList env regs prog outReg = IR1Expr.eval env e := by
  induction e generalizing base regs with
  | literal v =>
    simp [compileIR1, IR3Program.execList, IR3Program.execInstruction, IR1Expr.eval]
  | binding id =>
    simp [compileIR1, IR3Program.execList, IR3Program.execInstruction, IR1Expr.eval]
  | unary op operand ih =>
    have ih1 := ih base regs
    rcases h1 : compileIR1 operand base with ⟨p1, r1, next1⟩
    rw [h1] at ih1
    dsimp only at ih1
    simp only [compileIR1, h1, IR3Program.execList_append, IR1Expr.eval]
    simp only [IR3Program.execList, List.foldl_cons, List.foldl_nil, IR3Program.execInstruction, ↓reduceIte]
    change (match IR3Program.execList env regs p1 r1 with
            | some v => some (evalUnaryOp op v)
            | _ => none) = _
    rw [ih1]
    cases IR1Expr.eval env operand <;> rfl
  | binary op l r ihl ihr =>
    have hbl := compileIR1_bounds l base
    have hll := ihl base regs
    rcases hl : compileIR1 l base with ⟨pl, rl, next1⟩
    rw [hl] at hbl hll
    dsimp only at hbl hll
    rcases hbl with ⟨_, hrl_n1, _⟩
    let regs1 := IR3Program.execList env regs pl
    have hbr := compileIR1_bounds r next1
    have hrr := ihr next1 regs1
    rcases hr : compileIR1 r next1 with ⟨pr, rr, next2⟩
    rw [hr] at hbr hrr
    dsimp only at hbr hrr
    rcases hbr with ⟨_, _, hpr_bounds⟩
    have h_rl_preserved : IR3Program.execList env regs1 pr rl = regs1 rl := by
      apply IR3Program.execList_preserves_below
      intro instr hm
      have ⟨hlo, _⟩ := hpr_bounds instr hm
      omega
    simp only [compileIR1, hl, hr, IR3Program.execList_append, IR1Expr.eval]
    simp only [IR3Program.execList, List.foldl_cons, List.foldl_nil, IR3Program.execInstruction, ↓reduceIte]
    change (match IR3Program.execList env regs1 pr rl, IR3Program.execList env regs1 pr rr with
            | some lv, some rv => some (evalBinaryOp op lv rv)
            | _, _ => none) = _
    rw [h_rl_preserved, hrr]
    change (match IR3Program.execList env regs pl rl, IR1Expr.eval env r with
            | some lv, some rv => some (evalBinaryOp op lv rv)
            | _, _ => none) = _
    rw [hll]

/-- Total, verified translation witness generator for any `IR0Expr` and `scope_map`. -/
def generateWitness (ir0 : IR0Expr) (scope_map : String → Nat := fun _ => 0) :
    PipelineValidationWitness :=
  let ir1 := lowerIR0ToIR1 scope_map ir0
  let ir2 : IR2Expr := { expr := ir1, label := LabelClass.Public }
  let compiled := compileIR1 ir1 0
  let prog := compiled.1
  let outReg := compiled.2.1
  {
    ir0_expr := ir0,
    ir1_expr := ir1,
    ir2_expr := ir2,
    ir3_program := prog,
    result_register := outReg,
    ir0_to_ir1 := {
      ir0_expr := ir0,
      ir1_expr := ir1,
      scope_map := scope_map,
      equivalence := fun env0 env1 h_coh => lowerIR0ToIR1_correct scope_map ir0 env0 env1 h_coh
    },
    ir1_to_ir2 := {
      ir1_expr := ir1,
      ir2_expr := ir2,
      equivalence := fun _ => rfl
    },
    ir2_to_ir3 := {
      ir2_expr := ir2,
      ir3_program := prog,
      result_register := outReg,
      equivalence := by
        intro env
        have hc := compileIR1_correct ir1 0 env (fun _ => none)
        exact hc.symm
    },
    ir0_matches := rfl,
    ir1_matches := ⟨rfl, rfl⟩,
    ir2_matches := ⟨rfl, rfl⟩,
    ir3_matches := ⟨rfl, rfl⟩
  }

-- =============================================================================
-- SSA Phi-Node Branch-Join Soundness Lemma (bd-cixqu.7.8)
-- =============================================================================

/-- SSA phi node selecting between then-branch and else-branch register values. -/
def evalPhiJoin (cond : Bool) (thenVal elseVal : Option JSValue) : Option JSValue :=
  if cond then thenVal else elseVal

/-- Phi-node join preserves branch-selected expression evaluation deterministically. -/
theorem phi_branch_join_sound
    (env : IR1Expr.Env) (cond : Bool) (thenExpr elseExpr : IR1Expr) :
    evalPhiJoin cond (IR1Expr.eval env thenExpr) (IR1Expr.eval env elseExpr) =
    IR1Expr.eval env (if cond then thenExpr else elseExpr) := by
  cases cond <;> rfl

-- =============================================================================
-- Concrete Smoke Examples
-- =============================================================================

def testLiteral (value : JSValue) : IR0Expr := IR0Expr.literal value

def testBinary (op : BinaryOperator) (left right : JSValue) : IR0Expr :=
  IR0Expr.binary op (IR0Expr.literal left) (IR0Expr.literal right)

def testUnary (op : UnaryOperator) (operand : JSValue) : IR0Expr :=
  IR0Expr.unary op (IR0Expr.literal operand)

def example_1_plus_2 : IR0Expr :=
  testBinary BinaryOperator.Add (JSValue.number 1) (JSValue.number 2)

def example_not_true : IR0Expr :=
  testUnary UnaryOperator.LogicalNot (JSValue.boolean true)

theorem example_1_plus_2_verified :
    let w := generateWitness example_1_plus_2
    IR3Program.eval (fun _ => none) w.ir3_program w.result_register = some (JSValue.number 3) := by
  decide
