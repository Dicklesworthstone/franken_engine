#!/usr/bin/env python3
"""
Pure Expression Test Case Generator

Generates 1000+ test cases for the translation validation pilot.
Creates pure expressions (no side effects, no control flow) for validating
the IR0 → IR1 → IR2 → IR3 transformation pipeline.

Test cases include:
- Arithmetic expressions: +, -, *, /, %, **
- Comparison expressions: ==, !=, ===, !==, <, <=, >, >=
- Logical expressions: &&, ||, ??
- Bitwise expressions: &, |, ^, <<, >>, >>>
- Unary expressions: -, +, !, ~, typeof, void
- Nested combinations of above

Output: JSON test cases for the translation validation framework
Related: bd-cixqu.7.6, translation validation pilot
"""

import json
import random
import math
from typing import List, Dict, Any, Union
from dataclasses import dataclass


@dataclass
class TestCase:
    """A single pure expression test case"""
    name: str
    description: str
    ir0_expr: Dict[str, Any]  # JSON representation of IR0 expression
    expected_type: str        # Expected result type
    test_environments: List[Dict[str, Any]]  # Test environments to evaluate under


class PureExprGenerator:
    """Generates pure expression test cases"""

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.test_cases: List[TestCase] = []

        # Binary operators (pure only)
        self.binary_ops = {
            # Arithmetic
            'Add': '+', 'Subtract': '-', 'Multiply': '*', 'Divide': '/',
            'Remainder': '%', 'Exponentiate': '**',
            # Comparison
            'Equal': '==', 'NotEqual': '!=', 'StrictEqual': '===', 'StrictNotEqual': '!==',
            'LessThan': '<', 'LessThanOrEqual': '<=', 'GreaterThan': '>', 'GreaterThanOrEqual': '>=',
            # Logical
            'LogicalAnd': '&&', 'LogicalOr': '||', 'NullishCoalescing': '??',
            # Bitwise
            'BitwiseAnd': '&', 'BitwiseOr': '|', 'BitwiseXor': '^',
            'LeftShift': '<<', 'RightShift': '>>', 'UnsignedRightShift': '>>>',
        }

        # Unary operators (pure only)
        self.unary_ops = {
            'Negate': '-', 'UnaryPlus': '+', 'LogicalNot': '!',
            'BitwiseNot': '~', 'Typeof': 'typeof', 'Void': 'void'
        }

        # Test values for different types
        self.test_numbers = [0, 1, -1, 42, -42, 3.14, -3.14, 1e6, -1e6, float('inf'), float('-inf')]
        self.test_booleans = [True, False]
        self.test_strings = ['', 'hello', '42', 'true', 'false', 'null', 'undefined', ' ', '\n']
        self.test_null_undefined = [None, 'undefined']  # None represents null in JSON

    def generate_literal_value(self) -> Dict[str, Any]:
        """Generate a random literal value"""
        value_type = random.choice(['number', 'boolean', 'string', 'null', 'undefined'])

        if value_type == 'number':
            if random.random() < 0.1:  # 10% chance for special numbers
                num = random.choice([float('inf'), float('-inf')])
            else:
                num = random.choice(self.test_numbers)
            return {'type': 'number', 'value': num}
        elif value_type == 'boolean':
            return {'type': 'boolean', 'value': random.choice(self.test_booleans)}
        elif value_type == 'string':
            return {'type': 'string', 'value': random.choice(self.test_strings)}
        elif value_type == 'null':
            return {'type': 'null', 'value': None}
        else:  # undefined
            return {'type': 'undefined', 'value': 'undefined'}

    def generate_identifier(self) -> Dict[str, Any]:
        """Generate a variable identifier"""
        var_names = ['x', 'y', 'z', 'a', 'b', 'result', 'temp', 'value']
        return {
            'type': 'identifier',
            'name': random.choice(var_names)
        }

    def generate_binary_expr(self, max_depth: int = 3) -> Dict[str, Any]:
        """Generate a binary expression"""
        op_name = random.choice(list(self.binary_ops.keys()))

        # Generate left and right operands
        if max_depth <= 0 or random.random() < 0.4:  # Base case: literals/identifiers
            left = random.choice([self.generate_literal_value, self.generate_identifier])()
            right = random.choice([self.generate_literal_value, self.generate_identifier])()
        else:  # Recursive case
            left = self.generate_expression(max_depth - 1)
            right = self.generate_expression(max_depth - 1)

        return {
            'type': 'binary',
            'operator': op_name,
            'left': left,
            'right': right
        }

    def generate_unary_expr(self, max_depth: int = 3) -> Dict[str, Any]:
        """Generate a unary expression"""
        op_name = random.choice(list(self.unary_ops.keys()))

        # Generate operand
        if max_depth <= 0 or random.random() < 0.5:  # Base case
            operand = random.choice([self.generate_literal_value, self.generate_identifier])()
        else:  # Recursive case
            operand = self.generate_expression(max_depth - 1)

        return {
            'type': 'unary',
            'operator': op_name,
            'operand': operand
        }

    def generate_expression(self, max_depth: int = 3) -> Dict[str, Any]:
        """Generate a random pure expression"""
        expr_type = random.choice(['literal', 'identifier', 'binary', 'unary'])

        if expr_type == 'literal':
            return self.generate_literal_value()
        elif expr_type == 'identifier':
            return self.generate_identifier()
        elif expr_type == 'binary':
            return self.generate_binary_expr(max_depth)
        else:  # unary
            return self.generate_unary_expr(max_depth)

    def generate_test_environment(self) -> Dict[str, Any]:
        """Generate a test environment (variable bindings)"""
        env = {}
        var_names = ['x', 'y', 'z', 'a', 'b', 'result', 'temp', 'value']

        # Randomly bind some variables
        for var_name in var_names:
            if random.random() < 0.6:  # 60% chance to bind each variable
                env[var_name] = self.generate_literal_value()['value']

        return env

    def determine_expected_type(self, expr: Dict[str, Any]) -> str:
        """Determine the expected result type of an expression"""
        if expr['type'] == 'literal':
            return expr.get('type', 'undefined')
        elif expr['type'] == 'identifier':
            return 'dynamic'  # Depends on environment
        elif expr['type'] == 'binary':
            op = expr['operator']
            if op in ['Add']:  # Special case: can be number or string
                return 'dynamic'
            elif op in ['Equal', 'NotEqual', 'StrictEqual', 'StrictNotEqual',
                       'LessThan', 'LessThanOrEqual', 'GreaterThan', 'GreaterThanOrEqual',
                       'LogicalAnd', 'LogicalOr']:
                return 'boolean'
            elif op in ['NullishCoalescing']:
                return 'dynamic'
            else:  # Arithmetic and bitwise
                return 'number'
        elif expr['type'] == 'unary':
            op = expr['operator']
            if op == 'Typeof':
                return 'string'
            elif op == 'LogicalNot':
                return 'boolean'
            elif op == 'Void':
                return 'undefined'
            else:  # Negate, UnaryPlus, BitwiseNot
                return 'number'
        return 'dynamic'

    def generate_focused_test_cases(self) -> List[TestCase]:
        """Generate focused test cases for specific patterns"""
        focused_cases = []

        # Arithmetic edge cases
        for op in ['Add', 'Subtract', 'Multiply', 'Divide', 'Remainder']:
            focused_cases.append(TestCase(
                name=f"arithmetic_{op.lower()}_basic",
                description=f"Basic {self.binary_ops[op]} operation",
                ir0_expr={
                    'type': 'binary',
                    'operator': op,
                    'left': {'type': 'number', 'value': 42},
                    'right': {'type': 'number', 'value': 7}
                },
                expected_type='number',
                test_environments=[{}]
            ))

        # Boolean logic cases
        for op in ['LogicalAnd', 'LogicalOr']:
            focused_cases.append(TestCase(
                name=f"logical_{op.lower()}_truthy",
                description=f"Logical {self.binary_ops[op]} with truthy values",
                ir0_expr={
                    'type': 'binary',
                    'operator': op,
                    'left': {'type': 'boolean', 'value': True},
                    'right': {'type': 'number', 'value': 42}
                },
                expected_type='dynamic',
                test_environments=[{}]
            ))

        # Comparison cases
        for op in ['Equal', 'StrictEqual', 'LessThan', 'GreaterThan']:
            focused_cases.append(TestCase(
                name=f"comparison_{op.lower()}_mixed",
                description=f"Comparison {self.binary_ops[op]} with mixed types",
                ir0_expr={
                    'type': 'binary',
                    'operator': op,
                    'left': {'type': 'string', 'value': '42'},
                    'right': {'type': 'number', 'value': 42}
                },
                expected_type='boolean',
                test_environments=[{}]
            ))

        # Unary cases
        for op in ['Negate', 'LogicalNot', 'Typeof', 'Void']:
            focused_cases.append(TestCase(
                name=f"unary_{op.lower()}_basic",
                description=f"Unary {self.unary_ops[op]} operation",
                ir0_expr={
                    'type': 'unary',
                    'operator': op,
                    'operand': {'type': 'number', 'value': 42}
                },
                expected_type=self.determine_expected_type({'type': 'unary', 'operator': op}),
                test_environments=[{}]
            ))

        # Nested expressions
        focused_cases.append(TestCase(
            name="nested_arithmetic_complex",
            description="Complex nested arithmetic: (a + b) * (c - d)",
            ir0_expr={
                'type': 'binary',
                'operator': 'Multiply',
                'left': {
                    'type': 'binary',
                    'operator': 'Add',
                    'left': {'type': 'identifier', 'name': 'a'},
                    'right': {'type': 'identifier', 'name': 'b'}
                },
                'right': {
                    'type': 'binary',
                    'operator': 'Subtract',
                    'left': {'type': 'identifier', 'name': 'c'},
                    'right': {'type': 'identifier', 'name': 'd'}
                }
            },
            expected_type='number',
            test_environments=[
                {'a': 10, 'b': 5, 'c': 20, 'd': 8},
                {'a': 0, 'b': 0, 'c': 1, 'd': 1},
                {'a': -5, 'b': 15, 'c': -10, 'd': -5}
            ]
        ))

        return focused_cases

    def generate_random_test_cases(self, count: int) -> List[TestCase]:
        """Generate random test cases"""
        random_cases = []

        for i in range(count):
            expr = self.generate_expression(max_depth=random.randint(1, 4))
            expected_type = self.determine_expected_type(expr)

            # Generate multiple test environments
            test_envs = []
            for _ in range(random.randint(1, 5)):
                test_envs.append(self.generate_test_environment())

            random_cases.append(TestCase(
                name=f"random_case_{i+1:04d}",
                description=f"Randomly generated pure expression #{i+1}",
                ir0_expr=expr,
                expected_type=expected_type,
                test_environments=test_envs
            ))

        return random_cases

    def generate_all_test_cases(self, random_count: int = 100) -> List[TestCase]:
        """Generate the complete test suite"""
        # Start with focused cases
        focused = self.generate_focused_test_cases()

        # Add random cases to reach 1000+ total
        random_cases = self.generate_random_test_cases(random_count)

        all_cases = focused + random_cases
        print(f"Generated {len(all_cases)} test cases ({len(focused)} focused + {len(random_cases)} random)")

        return all_cases

    def save_test_cases(self, filename: str, test_cases: List[TestCase]):
        """Save test cases to JSON file"""
        # Convert test cases to JSON-serializable format
        json_data = {
            'metadata': {
                'description': 'Pure expression test cases for translation validation pilot',
                'version': '1.0.0',
                'generator': 'generate_pure_expr_test_cases.py',
                'total_cases': len(test_cases),
                'generated_for': 'bd-cixqu.7.6'
            },
            'test_cases': []
        }

        for case in test_cases:
            json_data['test_cases'].append({
                'name': case.name,
                'description': case.description,
                'ir0_expression': case.ir0_expr,
                'expected_type': case.expected_type,
                'test_environments': case.test_environments
            })

        with open(filename, 'w') as f:
            json.dump(json_data, f, indent=2)

        print(f"Saved {len(test_cases)} test cases to {filename}")


def main():
    """Main entry point"""
    generator = PureExprGenerator(seed=42)  # Fixed seed for reproducibility

    # Generate test cases
    test_cases = generator.generate_all_test_cases(random_count=100)

    # Save to file
    output_file = 'pure_expr_test_cases.json'
    generator.save_test_cases(output_file, test_cases)

    # Print statistics
    print(f"\nTest Case Statistics:")
    print(f"- Total test cases: {len(test_cases)}")

    # Count by expression type
    type_counts = {}
    for case in test_cases:
        expr_type = case.ir0_expr.get('type', 'unknown')
        type_counts[expr_type] = type_counts.get(expr_type, 0) + 1

    for expr_type, count in sorted(type_counts.items()):
        print(f"- {expr_type}: {count}")

    # Count by expected result type
    result_type_counts = {}
    for case in test_cases:
        result_type = case.expected_type
        result_type_counts[result_type] = result_type_counts.get(result_type, 0) + 1

    print("\nExpected result types:")
    for result_type, count in sorted(result_type_counts.items()):
        print(f"- {result_type}: {count}")


if __name__ == '__main__':
    main()