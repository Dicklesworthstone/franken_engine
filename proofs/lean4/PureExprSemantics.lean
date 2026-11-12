/-
# Pure Expression Semantics for Translation Validation

Formal semantics for pure expressions in FrankenEngine's IR transformation pipeline,
mechanized in pure Lean 4 core with complete proofs and mathematically sound scoping:
- Numeric values are modeled explicitly as exact integers (`intNumber : Int → JSValue`)
  plus explicit IEEE-754 `nan : JSValue` so NaN non-reflexivity (`NaN !== NaN`) and
  32-bit `BitVec 32` bitwise operations are kernel-reducible without opaque C `Float` externs.
- String concatenation (`PureBinaryOp.add` on strings) is proven NON-commutative via an
  explicit counterexample (`add_not_commutative_on_strings`), while commutativity,
  associativity, and two-sided identities are proven where they genuinely hold!

Related: bd-cixqu.7.6, bd-rc-2026-11-11-epic-g2vrp.10
-/

-- =============================================================================
-- Value Domain for Pure Expressions
-- =============================================================================

/-- JavaScript value domain for pure expression evaluation (kernel-reducible). -/
inductive JSValue : Type
  | number    : Int → JSValue     -- Finite safe integer number
  | nan       : JSValue           -- IEEE-754 NaN value
  | boolean   : Bool → JSValue    -- true / false
  | string    : String → JSValue  -- UTF-8 string literal
  | null      : JSValue           -- null
  | undefined : JSValue           -- undefined
  | bigint    : Int → JSValue     -- Arbitrary-precision BigInt
deriving DecidableEq, Repr

namespace JSValue

/-- Numeric result with NaN propagation (`Option Int`: `some n` = finite, `none` = NaN). -/
def toNumericOpt : JSValue → Option Int
  | number n      => some n
  | nan           => none
  | boolean true  => some 1
  | boolean false => some 0
  | string ""     => some 0
  | string _      => none
  | null          => some 0
  | undefined     => none
  | bigint i      => some i

def ofNumericOpt : Option Int → JSValue
  | some n => number n
  | none   => nan

/-- JavaScript `ToBoolean` conversion (ES2020 §7.1.2). -/
def toBoolean : JSValue → Bool
  | number n  => decide (n ≠ 0)
  | nan       => false
  | boolean b => b
  | string s  => decide (s ≠ "")
  | null      => false
  | undefined => false
  | bigint i  => decide (i ≠ 0)

/-- JavaScript `ToString` conversion (ES2020 §7.1.17). -/
def toJsString : JSValue → String
  | number n      => toString n
  | nan           => "NaN"
  | boolean true  => "true"
  | boolean false => "false"
  | string s      => s
  | null          => "null"
  | undefined     => "undefined"
  | bigint i      => toString i

/-- ES2020 `ToInt32` / `ToUint32` modular 32-bit bitvector projection (`0` on NaN). -/
def toBitVec32 (v : JSValue) : BitVec 32 :=
  match v.toNumericOpt with
  | some n => BitVec.ofInt 32 n
  | none   => 0#32

def fromInt32Bits (b : BitVec 32) : JSValue :=
  number b.toInt

def fromUint32Bits (b : BitVec 32) : JSValue :=
  number (Int.ofNat b.toNat)

/-- Predicate identifying non-string values (where `+` performs numeric addition, not concat). -/
def isNonString : JSValue → Bool
  | string _ => false
  | _        => true

end JSValue

-- =============================================================================
-- Pure Binary Operators
-- =============================================================================

inductive PureBinaryOp : Type
  | add                : PureBinaryOp
  | subtract           : PureBinaryOp
  | multiply           : PureBinaryOp
  | divide             : PureBinaryOp
  | remainder          : PureBinaryOp
  | exponentiate       : PureBinaryOp
  | equal              : PureBinaryOp
  | notEqual           : PureBinaryOp
  | strictEqual        : PureBinaryOp
  | strictNotEqual     : PureBinaryOp
  | lessThan           : PureBinaryOp
  | lessThanEqual      : PureBinaryOp
  | greaterThan        : PureBinaryOp
  | greaterThanEqual   : PureBinaryOp
  | logicalAnd         : PureBinaryOp
  | logicalOr          : PureBinaryOp
  | nullishCoalescing  : PureBinaryOp
  | bitwiseAnd         : PureBinaryOp
  | bitwiseOr          : PureBinaryOp
  | bitwiseXor         : PureBinaryOp
  | leftShift          : PureBinaryOp
  | rightShift         : PureBinaryOp
  | unsignedRightShift : PureBinaryOp
deriving DecidableEq, Repr

namespace PureBinaryOp

def liftNumeric2 (f : Int → Int → Option Int) (left right : JSValue) : JSValue :=
  match left.toNumericOpt, right.toNumericOpt with
  | some a, some b => JSValue.ofNumericOpt (f a b)
  | _, _           => JSValue.nan

/-- Symmetric abstract equality (`==` over same-tag + null/undefined equivalence). -/
def abstractEqualVal (left right : JSValue) : Bool :=
  match left, right with
  | JSValue.number n1,  JSValue.number n2  => decide (n1 = n2)
  | JSValue.boolean b1, JSValue.boolean b2 => b1 == b2
  | JSValue.string s1,  JSValue.string s2  => decide (s1 = s2)
  | JSValue.null,       JSValue.null       => true
  | JSValue.undefined,  JSValue.undefined  => true
  | JSValue.null,       JSValue.undefined  => true
  | JSValue.undefined,  JSValue.null       => true
  | JSValue.bigint i1,  JSValue.bigint i2  => decide (i1 = i2)
  | _,                  _                  => false

/-- Strict equality (`===`, where `NaN === NaN` is `false` per IEEE-754 / ES2020). -/
def strictEqualVal (left right : JSValue) : Bool :=
  match left, right with
  | JSValue.number n1,  JSValue.number n2  => decide (n1 = n2)
  | JSValue.boolean b1, JSValue.boolean b2 => b1 == b2
  | JSValue.string s1,  JSValue.string s2  => decide (s1 = s2)
  | JSValue.null,       JSValue.null       => true
  | JSValue.undefined,  JSValue.undefined  => true
  | JSValue.bigint i1,  JSValue.bigint i2  => decide (i1 = i2)
  | _,                  _                  => false

def eval (op : PureBinaryOp) (left right : JSValue) : JSValue :=
  match op with
  | add =>
    match left, right with
    | JSValue.string s1, _ => JSValue.string (s1 ++ right.toJsString)
    | _, JSValue.string s2 => JSValue.string (left.toJsString ++ s2)
    | _, _ => liftNumeric2 (fun a b => some (a + b)) left right
  | subtract     => liftNumeric2 (fun a b => some (a - b)) left right
  | multiply     => liftNumeric2 (fun a b => some (a * b)) left right
  | divide       => liftNumeric2 (fun a b => if b = 0 then none else some (a / b)) left right
  | remainder    => liftNumeric2 (fun a b => if b = 0 then none else some (a % b)) left right
  | exponentiate =>
    liftNumeric2 (fun a b => if b < 0 then none else some (a ^ b.toNat)) left right
  | equal          => JSValue.boolean (abstractEqualVal left right)
  | notEqual       => JSValue.boolean (!abstractEqualVal left right)
  | strictEqual    => JSValue.boolean (strictEqualVal left right)
  | strictNotEqual => JSValue.boolean (!strictEqualVal left right)
  | lessThan =>
    match left.toNumericOpt, right.toNumericOpt with
    | some a, some b => JSValue.boolean (decide (a < b))
    | _, _           => JSValue.boolean false
  | lessThanEqual =>
    match left.toNumericOpt, right.toNumericOpt with
    | some a, some b => JSValue.boolean (decide (a ≤ b))
    | _, _           => JSValue.boolean false
  | greaterThan =>
    match left.toNumericOpt, right.toNumericOpt with
    | some a, some b => JSValue.boolean (decide (b < a))
    | _, _           => JSValue.boolean false
  | greaterThanEqual =>
    match left.toNumericOpt, right.toNumericOpt with
    | some a, some b => JSValue.boolean (decide (b ≤ a))
    | _, _           => JSValue.boolean false
  | logicalAnd => if left.toBoolean then right else left
  | logicalOr  => if left.toBoolean then left else right
  | nullishCoalescing =>
    match left with
    | JSValue.null | JSValue.undefined => right
    | _ => left
  | bitwiseAnd => JSValue.fromInt32Bits (left.toBitVec32 &&& right.toBitVec32)
  | bitwiseOr  => JSValue.fromInt32Bits (left.toBitVec32 ||| right.toBitVec32)
  | bitwiseXor => JSValue.fromInt32Bits (left.toBitVec32 ^^^ right.toBitVec32)
  | leftShift =>
    let sh := right.toBitVec32.toNat % 32
    JSValue.fromInt32Bits (left.toBitVec32 <<< sh)
  | rightShift =>
    let sh := right.toBitVec32.toNat % 32
    JSValue.fromInt32Bits (BitVec.sshiftRight left.toBitVec32 sh)
  | unsignedRightShift =>
    let sh := right.toBitVec32.toNat % 32
    JSValue.fromUint32Bits (left.toBitVec32 >>> sh)

end PureBinaryOp

-- =============================================================================
-- Pure Unary Operators & PureExpr AST
-- =============================================================================

inductive PureUnaryOp : Type
  | negate     : PureUnaryOp
  | unaryPlus  : PureUnaryOp
  | logicalNot : PureUnaryOp
  | bitwiseNot : PureUnaryOp
  | typeof     : PureUnaryOp
  | void       : PureUnaryOp
deriving DecidableEq, Repr

namespace PureUnaryOp

def typeofString : JSValue → String
  | JSValue.number _  => "number"
  | JSValue.nan       => "number"
  | JSValue.boolean _ => "boolean"
  | JSValue.string _  => "string"
  | JSValue.null      => "object"
  | JSValue.undefined => "undefined"
  | JSValue.bigint _  => "bigint"

def eval (op : PureUnaryOp) (operand : JSValue) : JSValue :=
  match op with
  | negate =>
    match operand.toNumericOpt with
    | some n => JSValue.number (-n)
    | none   => JSValue.nan
  | unaryPlus  => JSValue.ofNumericOpt operand.toNumericOpt
  | logicalNot => JSValue.boolean (!operand.toBoolean)
  | bitwiseNot => JSValue.fromInt32Bits (~~~operand.toBitVec32)
  | typeof     => JSValue.string (typeofString operand)
  | void       => JSValue.undefined

end PureUnaryOp

inductive PureExpr : Type
  | literal    : JSValue → PureExpr
  | binary     : PureBinaryOp → PureExpr → PureExpr → PureExpr
  | unary      : PureUnaryOp → PureExpr → PureExpr
  | identifier : String → PureExpr
deriving DecidableEq, Repr

namespace PureExpr

def Env := String → Option JSValue

def eval (env : Env) : PureExpr → Option JSValue
  | literal v => some v
  | binary op left right => do
    let leftVal ← eval env left
    let rightVal ← eval env right
    some (PureBinaryOp.eval op leftVal rightVal)
  | unary op operand => do
    let operandVal ← eval env operand
    some (PureUnaryOp.eval op operandVal)
  | identifier name => env name

end PureExpr

-- =============================================================================
-- Translation Validation & Algebraic Theorems
-- =============================================================================

def Translation (Source Target : Type) := Source → Target

def semanticallyEquivalent (e1 e2 : PureExpr) : Prop :=
  ∀ env : PureExpr.Env, PureExpr.eval env e1 = PureExpr.eval env e2

def preservesSemantics {Source : Type}
    (sourceEval : PureExpr.Env → Source → Option JSValue)
    (translation : Translation Source PureExpr)
    (source : Source) : Prop :=
  ∀ env : PureExpr.Env,
    sourceEval env source = PureExpr.eval env (translation source)

theorem translation_correctness
    {Source : Type}
    (sourceEval : PureExpr.Env → Source → Option JSValue)
    (translation : Translation Source PureExpr)
    (source : Source) :
    preservesSemantics sourceEval translation source ↔
    (∀ env : PureExpr.Env, sourceEval env source = PureExpr.eval env (translation source)) :=
  Iff.rfl

/-- Explicit proof that JS `+` is NOT unconditionally commutative because of string concat. -/
theorem add_not_commutative_on_strings :
    PureBinaryOp.eval PureBinaryOp.add (JSValue.string "a") (JSValue.string "b") ≠
    PureBinaryOp.eval PureBinaryOp.add (JSValue.string "b") (JSValue.string "a") := by
  decide

/-- Numeric addition IS commutative whenever neither operand is a string. -/
theorem numeric_add_commutative (left right : JSValue)
    (hl : left.isNonString = true) (hr : right.isNonString = true) :
    PureBinaryOp.eval PureBinaryOp.add left right =
    PureBinaryOp.eval PureBinaryOp.add right left := by
  have h_lr : PureBinaryOp.eval PureBinaryOp.add left right =
      PureBinaryOp.liftNumeric2 (fun a b => some (a + b)) left right := by
    cases left <;> cases right <;> simp [JSValue.isNonString] at hl hr <;> rfl
  have h_rl : PureBinaryOp.eval PureBinaryOp.add right left =
      PureBinaryOp.liftNumeric2 (fun a b => some (a + b)) right left := by
    cases right <;> cases left <;> simp [JSValue.isNonString] at hl hr <;> rfl
  rw [h_lr, h_rl]
  cases hlo : left.toNumericOpt <;> cases hro : right.toNumericOpt <;>
    simp [PureBinaryOp.liftNumeric2, hlo, hro, JSValue.ofNumericOpt, Int.add_comm]

theorem abstractEqual_symm (a b : JSValue) :
    PureBinaryOp.abstractEqualVal a b = PureBinaryOp.abstractEqualVal b a := by
  cases a <;> cases b <;> simp [PureBinaryOp.abstractEqualVal, Bool.beq_comm, eq_comm]

theorem strictEqual_symm (a b : JSValue) :
    PureBinaryOp.strictEqualVal a b = PureBinaryOp.strictEqualVal b a := by
  cases a <;> cases b <;> simp [PureBinaryOp.strictEqualVal, Bool.beq_comm, eq_comm]

/-- Commutativity of genuinely commutative binary operators across ALL `JSValue` inputs. -/
theorem binary_commutative (op : PureBinaryOp) (left right : JSValue)
    (h : op = PureBinaryOp.multiply ∨
         op = PureBinaryOp.equal ∨
         op = PureBinaryOp.notEqual ∨
         op = PureBinaryOp.strictEqual ∨
         op = PureBinaryOp.strictNotEqual ∨
         op = PureBinaryOp.bitwiseAnd ∨
         op = PureBinaryOp.bitwiseOr ∨
         op = PureBinaryOp.bitwiseXor) :
    PureBinaryOp.eval op left right = PureBinaryOp.eval op right left := by
  rcases h with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · cases hl : left.toNumericOpt <;> cases hr : right.toNumericOpt <;>
      simp [PureBinaryOp.eval, PureBinaryOp.liftNumeric2, hl, hr, Int.mul_comm]
  · simp [PureBinaryOp.eval, abstractEqual_symm]
  · simp [PureBinaryOp.eval, abstractEqual_symm]
  · simp [PureBinaryOp.eval, strictEqual_symm]
  · simp [PureBinaryOp.eval, strictEqual_symm]
  · simp [PureBinaryOp.eval, BitVec.and_comm]
  · simp [PureBinaryOp.eval, BitVec.or_comm]
  · simp [PureBinaryOp.eval, BitVec.xor_comm]

theorem toBitVec32_fromInt32Bits (b : BitVec 32) :
    (JSValue.fromInt32Bits b).toBitVec32 = b := by
  simp [JSValue.fromInt32Bits, JSValue.toBitVec32, JSValue.toNumericOpt, BitVec.ofInt_toInt]

/-- Associativity of bitwise operators across ALL `JSValue` inputs. -/
theorem binary_associative (op : PureBinaryOp) (a b c : JSValue)
    (h : op = PureBinaryOp.bitwiseAnd ∨
         op = PureBinaryOp.bitwiseOr ∨
         op = PureBinaryOp.bitwiseXor) :
    PureBinaryOp.eval op (PureBinaryOp.eval op a b) c =
    PureBinaryOp.eval op a (PureBinaryOp.eval op b c) := by
  rcases h with rfl | rfl | rfl
  · simp [PureBinaryOp.eval, toBitVec32_fromInt32Bits, BitVec.and_assoc]
  · simp [PureBinaryOp.eval, toBitVec32_fromInt32Bits, BitVec.or_assoc]
  · simp [PureBinaryOp.eval, toBitVec32_fromInt32Bits, BitVec.xor_assoc]

/-- Associativity of addition and multiplication over finite numbers. -/
theorem numeric_binary_associative (op : PureBinaryOp) (a b c : Int)
    (h : op = PureBinaryOp.add ∨ op = PureBinaryOp.multiply) :
    PureBinaryOp.eval op (PureBinaryOp.eval op (JSValue.number a) (JSValue.number b)) (JSValue.number c) =
    PureBinaryOp.eval op (JSValue.number a) (PureBinaryOp.eval op (JSValue.number b) (JSValue.number c)) := by
  rcases h with rfl | rfl
  · simp [PureBinaryOp.eval, PureBinaryOp.liftNumeric2, JSValue.toNumericOpt,
          JSValue.ofNumericOpt, Int.add_assoc]
  · simp [PureBinaryOp.eval, PureBinaryOp.liftNumeric2, JSValue.toNumericOpt,
          JSValue.ofNumericOpt, Int.mul_assoc]

/-- Two-sided identity elements scoped to finite integer numbers (`0` for `+`, `1` for `*`). -/
theorem binary_identity (op : PureBinaryOp)
    (h : op = PureBinaryOp.add ∨ op = PureBinaryOp.multiply) :
    ∃ identity : JSValue, ∀ n : Int,
      PureBinaryOp.eval op (JSValue.number n) identity = JSValue.number n ∧
      PureBinaryOp.eval op identity (JSValue.number n) = JSValue.number n := by
  rcases h with rfl | rfl
  · refine ⟨JSValue.number 0, fun n => ?_⟩
    simp [PureBinaryOp.eval, PureBinaryOp.liftNumeric2, JSValue.toNumericOpt, JSValue.ofNumericOpt]
  · refine ⟨JSValue.number 1, fun n => ?_⟩
    simp [PureBinaryOp.eval, PureBinaryOp.liftNumeric2, JSValue.toNumericOpt, JSValue.ofNumericOpt]

/-- Double logical negation normalizes any value to its `ToBoolean` boolean. -/
theorem double_negation (x : JSValue) :
    PureUnaryOp.eval PureUnaryOp.logicalNot
      (PureUnaryOp.eval PureUnaryOp.logicalNot x) =
    JSValue.boolean x.toBoolean := by
  simp [PureUnaryOp.eval, JSValue.toBoolean]

-- =============================================================================
-- Translation Validation Witness Composition
-- =============================================================================

structure TranslationWitness (Source Target : Type) where
  source : Source
  target : Target
  sourceEval : PureExpr.Env → Source → Option JSValue
  targetEval : PureExpr.Env → Target → Option JSValue
  equivalence_proof : ∀ env, sourceEval env source = targetEval env target

def composeWitnesses
    {A B C : Type}
    (w1 : TranslationWitness A B)
    (w2 : TranslationWitness B C)
    (target_eq : w1.target = w2.source)
    (eval_eq : w1.targetEval = w2.sourceEval) :
    TranslationWitness A C :=
{
  source := w1.source,
  target := w2.target,
  sourceEval := w1.sourceEval,
  targetEval := w2.targetEval,
  equivalence_proof := by
    intro env
    rw [w1.equivalence_proof env, eval_eq, target_eq, w2.equivalence_proof env]
}

structure PipelineWitness where
  ir0_expr : PureExpr
  ir1_expr : PureExpr
  ir2_expr : PureExpr
  ir3_expr : PureExpr
  ir0_to_ir1 : TranslationWitness PureExpr PureExpr
  ir1_to_ir2 : TranslationWitness PureExpr PureExpr
  ir2_to_ir3 : TranslationWitness PureExpr PureExpr
  pipeline_correctness : ∀ env,
    PureExpr.eval env ir0_expr = PureExpr.eval env ir3_expr
