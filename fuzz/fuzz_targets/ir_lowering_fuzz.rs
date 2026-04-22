#![no_main]

use frankenengine_engine::ast::{
    Expression, Literal, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclarationKind,
    BinaryOperator, AssignmentOperator,
};
use frankenengine_engine::ir_contract::{Ir0Module, IrHeader, IrLevel, IrSchemaVersion};
use frankenengine_engine::lowering_pipeline::{lower_ir0_to_ir1, LoweringContext};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4 * 1024;
const MAX_STATEMENTS: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let goal = parse_goal(data);
    let tree = synthetic_syntax_tree(data, goal);
    let ir0 = Ir0Module::from_syntax_tree(tree, "fuzz-source");

    // Test IR0 to IR1 lowering (most fundamental transformation)
    let _ = lower_ir0_to_ir1(&ir0);

    // Test with lowering context for full pipeline
    let context = LoweringContext {
        trace_id: "fuzz-trace".to_string(),
        decision_id: "fuzz-decision".to_string(),
        policy_id: "fuzz-policy".to_string(),
        source_label: "fuzz-source".to_string(),
        replay_mode: false,
        debug_mode: false,
    };

    let _ = frankenengine_engine::lowering_pipeline::lower_ir0_to_ir3(&ir0, &context);
});

fn parse_goal(data: &[u8]) -> ParseGoal {
    if byte(data, 0) & 1 == 0 {
        ParseGoal::Script
    } else {
        ParseGoal::Module
    }
}

fn synthetic_syntax_tree(data: &[u8], goal: ParseGoal) -> SyntaxTree {
    let mut statements = Vec::new();

    for (index, chunk) in data[1..]
        .chunks(4)
        .take(MAX_STATEMENTS)
        .enumerate()
    {
        let opcode = chunk.first().copied().unwrap_or(0);
        let statement = synthetic_statement(opcode, index);
        statements.push(statement);
    }

    // Always include at least one statement to avoid EmptyIr0Body error
    if statements.is_empty() {
        statements.push(Statement::Expression(Expression::Literal(Literal::Number(42.0))));
    }

    SyntaxTree {
        goal,
        body: statements,
        span: SourceSpan { start: 0, end: 0 },
    }
}

fn synthetic_statement(opcode: u8, index: usize) -> Statement {
    match opcode % 12 {
        0 => Statement::Expression(Expression::Literal(Literal::Number(index as f64))),
        1 => Statement::Expression(Expression::Literal(Literal::String(format!("str_{index}")))),
        2 => Statement::Expression(Expression::Literal(Literal::Boolean(index % 2 == 0))),
        3 => Statement::Expression(Expression::Literal(Literal::Null)),
        4 => Statement::Expression(Expression::Literal(Literal::Undefined)),
        5 => Statement::VariableDeclaration {
            declarations: vec![variable_declarator(index)],
            kind: VariableDeclarationKind::Let,
        },
        6 => Statement::VariableDeclaration {
            declarations: vec![variable_declarator(index)],
            kind: VariableDeclarationKind::Const,
        },
        7 => Statement::VariableDeclaration {
            declarations: vec![variable_declarator(index)],
            kind: VariableDeclarationKind::Var,
        },
        8 => Statement::Expression(binary_expression(index)),
        9 => Statement::Block(vec![
            Statement::Expression(Expression::Literal(Literal::Number(index as f64))),
        ]),
        10 => Statement::If {
            test: Expression::Literal(Literal::Boolean(true)),
            consequent: Box::new(Statement::Expression(Expression::Literal(Literal::Number(1.0)))),
            alternate: Some(Box::new(Statement::Expression(Expression::Literal(Literal::Number(0.0))))),
        },
        _ => Statement::Return(Some(Expression::Literal(Literal::Number(index as f64)))),
    }
}

fn variable_declarator(index: usize) -> frankenengine_engine::ast::VariableDeclarator {
    frankenengine_engine::ast::VariableDeclarator {
        id: frankenengine_engine::ast::BindingPattern::Identifier(format!("v{index}")),
        initializer: Some(Expression::Literal(Literal::Number(index as f64))),
    }
}

fn binary_expression(index: usize) -> Expression {
    Expression::Binary {
        operator: match index % 4 {
            0 => BinaryOperator::Add,
            1 => BinaryOperator::Sub,
            2 => BinaryOperator::Mul,
            _ => BinaryOperator::Div,
        },
        left: Box::new(Expression::Literal(Literal::Number(index as f64))),
        right: Box::new(Expression::Literal(Literal::Number((index + 1) as f64))),
    }
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data[index % data.len()]
}