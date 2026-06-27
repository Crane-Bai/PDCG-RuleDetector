import json
import os
from typing import Dict, List, Any, Optional
from collections import deque, defaultdict
import sys
import time
from typing import Dict, List, Any, Optional
sys.stdout.reconfigure(encoding='utf-8')
os.system('chcp 65001 >nul')
class PDCGAnalyzer:
    """
    Parameterized Data-flow Call Graph (PDCG) Analyzer
    Generates call graph and data-flow analysis for JavaScript code based on AST structure
    """
    
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.node_id_counter = 0
        self.ast_cache = None
        
        # Node mapping
        self.ast_to_node = {}  # AST node -> generated node ID
        
        # Processing queue
        self.processing_queue = deque()
        
        # Added: Function definition symbol table
        self.function_definitions = {}  # function name -> definition node ID
    def analyze_pdcg_from_ast(self, ast_file_path: str) -> Dict[str, Any]:
        """Main analysis workflow"""
        print(f"Starting PDCG analysis: {ast_file_path}")
        
        # 1. Load AST
        if not self._load_ast(ast_file_path):
            return {"error": "Failed to load AST"}
        
        # 2. Create root node and initialize queue
        self._create_root_and_enqueue()
        
        # 3. Process queue, generate all nodes and edges
        self._process_queue()
        
        # 4. Validate and generate statistics
        result = self._validate_and_generate_stats()
        
        print(f"PDCG analysis completed: {len(self.nodes)} nodes, {len(self.edges)} edges")
        return result
    
    def _load_ast(self, ast_file_path: str) -> bool:
        """Load AST file"""
        try:
            with open(ast_file_path, 'r', encoding='utf-8') as f:
                ast_data = json.load(f)
            
            if not ast_data.get('success', False):
                print("AST parsing failed")
                return False
            
            self.ast_cache = ast_data['ast']['program']
            print(f"AST loaded successfully, program body contains {len(self.ast_cache.get('body', []))} top-level statements")
            return True
            
        except Exception as e:
            print(f"Failed to load AST: {e}")
            return False
    
    def _create_root_and_enqueue(self):
        """Create root node and initialize queue"""
        # Create file root node
        file_id = self._create_node('FILE', 'file')
        
        # Add program body to queue
        program_body = self.ast_cache.get('body', [])
        for stmt in program_body:
            if stmt is not None:  # Add None check
                self.processing_queue.append({
                    'ast_node': stmt,
                    'parent_id': file_id,
                    'context': 'top_level'
                })
        
        print(f"Root node created, queue initialized: {len(self.processing_queue)} pending items")
    def _process_queue(self):
        """Process queue"""
        level = 1
        
        while self.processing_queue:
            current_level_size = len(self.processing_queue)
            print(f"Processing level {level}, containing {current_level_size} nodes")
            
            for _ in range(current_level_size):
                if not self.processing_queue:
                    break
                
                item = self.processing_queue.popleft()
                self._process_queue_item(item)
            
            level += 1
            if level > 50:
                print(f"Maximum level limit reached, stopping processing")
                break
        
        print(f"Queue processing completed, total {level-1} levels processed")
    
    def _process_queue_item(self, item: Dict):
        """Process queue item"""
        # Add None check
        if not item or not isinstance(item, dict):
            return
            
        ast_node = item.get('ast_node')
        parent_id = item.get('parent_id')
        context = item.get('context')
        
        # Ensure ast_node is not None and is a dict
        if not ast_node or not isinstance(ast_node, dict):
            return
            
        node_type = ast_node.get('type')
        if not node_type:
            return
        
        # Dispatch processing based on node type
        if node_type == 'FunctionDeclaration':
            self._handle_function_declaration(ast_node, parent_id, context)
        elif node_type == 'ClassDeclaration':
            self._handle_class_declaration(ast_node, parent_id, context)
        elif node_type == 'CallExpression':
            self._handle_call_expression(ast_node, parent_id, context)
        elif node_type in ['FunctionExpression', 'ArrowFunctionExpression']:
            self._handle_function_expression(ast_node, parent_id, context)
        elif node_type == 'NewExpression':
            self._handle_new_expression(ast_node, parent_id, context)
        elif node_type == 'VariableDeclaration':
            self._handle_variable_declaration(ast_node, parent_id, context)
        elif node_type == 'ExpressionStatement':
            self._handle_expression_statement(ast_node, parent_id, context)
        elif node_type == 'AssignmentExpression':
        # Added: Recursively process assignment left and right
            left = ast_node.get('left')
            right = ast_node.get('right')
            if left:
                self._enqueue_child(left, parent_id, 'assignment_left')
            if right:
                self._enqueue_child(right, parent_id, 'assignment_right')
        elif node_type == 'MemberExpression':
        # Added: Recursively process object and property
            obj = ast_node.get('object')
            prop = ast_node.get('property')
            if obj:
                self._enqueue_child(obj, parent_id, 'member_object')
            if prop:
                self._enqueue_child(prop, parent_id, 'member_property')
        elif node_type in ['IfStatement', 'ForStatement', 'WhileStatement', 'BlockStatement']:
            self._handle_control_flow(ast_node, parent_id, context)
        else:
            self._handle_generic_node(ast_node, parent_id, context)

    def _handle_call_expression(self, ast_node: Dict, parent_id: str, context: str):
        """Process CallExpression - Core method"""
        call_analysis = self._analyze_call_structure(ast_node)
        call_id = self._create_node(
            'CALL',
            'call',
            callee_name=call_analysis['name'],
            is_chained=call_analysis['is_chained'],
            is_member_call=call_analysis['is_member'],
            call_depth=call_analysis['call_depth'],
            chain_position=call_analysis['chain_position']
        )
        self.ast_to_node[id(ast_node)] = call_id
    
        # Establish parent-child relationship (original logic unchanged)
        if call_analysis['is_chained']:
            base_call_ast = call_analysis.get('base_call_ast')
            if base_call_ast:
                base_call_id = self._ensure_call_processed(base_call_ast, parent_id, context)
                if base_call_id:
                    self._add_edge(base_call_id, call_id, 'chained_call')
                else:
                    edge_type = 'calls' if context in ['top_level', 'function_body'] else 'nested_in'
                    self._add_edge(parent_id, call_id, edge_type)
            else:
                edge_type = 'calls' if context in ['top_level', 'function_body'] else 'nested_in'
                self._add_edge(parent_id, call_id, edge_type)
        else:
            edge_type = 'calls' if context in ['top_level', 'function_body'] else 'nested_in'
            self._add_edge(parent_id, call_id, edge_type)
    
        # Added: Check and associate custom function calls
        callee = ast_node.get('callee', {})
        if callee.get('type') == 'Identifier':
            func_name_to_check = callee.get('name')
            if func_name_to_check and func_name_to_check in self.function_definitions:
                definition_node_id = self.function_definitions[func_name_to_check]
                self._add_edge(call_id, definition_node_id, 'resolves_to_def')
                #print(f"  Custom function call associated: {func_name_to_check}() -> {definition_node_id}")
    
        # Process arguments
        self._handle_call_arguments(ast_node.get('arguments', []), call_id)
    
        # Fix 1: Recursively process callee as CallExpression
        if callee:
            if callee.get('type') in ['FunctionExpression', 'ArrowFunctionExpression']:
                body = callee.get('body')
                if body:
                    self._enqueue_function_body(body, call_id)
            elif callee.get('type') == 'CallExpression':
                self._enqueue_child(callee, call_id, 'callee')
            elif callee.get('type') == 'MemberExpression':
                self._enqueue_child(callee, call_id, 'callee')
    def _ensure_call_processed(self, call_ast: Dict, parent_id: str, context: str) -> Optional[str]:
        """Ensure call has been processed, if not process immediately"""
        # Check if already processed
        call_id = self.ast_to_node.get(id(call_ast))
        if call_id:
            return call_id
        
        # If not processed, process immediately
        if call_ast.get('type') == 'CallExpression':
            self._handle_call_expression(call_ast, parent_id, context)
            return self.ast_to_node.get(id(call_ast))
        
        return None
    
    def _analyze_call_structure(self, ast_node: Dict) -> Dict:
        """Analyze call structure"""
        if ast_node.get('type') != 'CallExpression':
            return {
                'is_chained': False, 
                'name': 'unknown', 
                'display_name': 'unknown',
                'is_member': False,
                'call_depth': 0,
                'chain_position': 'unknown'
            }
        
        callee = ast_node.get('callee', {})
        
        if callee.get('type') == 'Identifier':
            # Simple call: func()
            name = callee.get('name', 'unknown')
            return {
                'name': name,
                'display_name': name,
                'is_chained': False,
                'is_member': False,
                'call_depth': 0,
                'chain_position': 'simple_call'
            }
        
        elif callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            prop_name = prop.get('name', 'unknown')
            
            if obj.get('type') == 'CallExpression':
                # Chained call: obj().method()
                base_analysis = self._analyze_call_chain_depth(obj)
                
                return {
                    'name': f"{base_analysis['name']}.{prop_name}",
                    'display_name': f"(...).{prop_name}",
                    'is_chained': True,
                    'is_member': True,
                    'call_depth': base_analysis['call_depth'] + 1,
                    'chain_position': 'chained',
                    'base_call_ast': obj
                }
            else:
                # Normal member call: obj.method()
                obj_name = self._extract_expression_name(obj)
                return {
                    'name': f"{obj_name}.{prop_name}",
                    'display_name': f"{obj_name}.{prop_name}",
                    'is_chained': False,
                    'is_member': True,
                    'call_depth': 0,
                    'chain_position': 'member_call'
                }
        
        return {
            'name': 'unknown',
            'display_name': 'unknown',
            'is_chained': False,
            'is_member': False,
            'call_depth': 0,
            'chain_position': 'unknown'
        }
    
    def _analyze_call_chain_depth(self, call_ast: Dict) -> Dict:
        """Analyze call chain depth"""
        if call_ast.get('type') != 'CallExpression':
            return {'call_depth': 0, 'name': 'unknown'}
        
        callee = call_ast.get('callee', {})
        
        if callee.get('type') == 'Identifier':
            # Base call
            return {
                'call_depth': 0,
                'name': callee.get('name', 'unknown')
            }
        
        elif callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            prop_name = prop.get('name', 'unknown')
            
            if obj.get('type') == 'CallExpression':
                # Recursively analyze deeper chain
                deeper_analysis = self._analyze_call_chain_depth(obj)
                return {
                    'call_depth': deeper_analysis['call_depth'] + 1,
                    'name': f"{deeper_analysis['name']}.{prop_name}"
                }
            else:
                # Member call as base
                obj_name = self._extract_expression_name(obj)
                return {
                    'call_depth': 0,
                    'name': f"{obj_name}.{prop_name}"
                }
        
        return {'call_depth': 0, 'name': 'unknown'}
    
    def _handle_call_arguments(self, args: List[Dict], call_id: str):
        """Process call arguments - Final simplified version"""
        for i, arg in enumerate(args):
            if arg is None:  # Add None check
                # Create null argument node
                arg_id = self._create_node(
                    'ARGUMENT',
                    'null',
                    arg_index=i,
                    content='null'
                )
                self._add_edge(call_id, arg_id, 'has_arg')
                continue
                
            # Remaining logic unchanged
            arg_content = self._extract_argument_content(arg)
            
            arg_id = self._create_node(
                'ARGUMENT',
                arg_content['type'],
                arg_index=i,
                content=arg_content['content']
            )
            
            self._add_edge(call_id, arg_id, 'has_arg')
            self._enqueue_child(arg, arg_id, 'call_argument')
    def _extract_argument_content(self, arg: Dict) -> Dict:
        """Extract argument content - Final version: Keep original content, simplify return structure"""
        if not arg:
            return {'type': 'null', 'content': 'null'}
        
        arg_type = arg.get('type')
        
        # Literal types - kept as original code
        if arg_type in ['Literal', 'StringLiteral', 'NumericLiteral', 'BooleanLiteral']:
            value = arg.get('value')
            if isinstance(value, str):
                return {'type': 'string', 'content': value}
            elif isinstance(value, (int, float)):
                return {'type': 'number', 'content': str(value)}
            elif isinstance(value, bool):
                # Keep JavaScript original boolean values
                return {'type': 'boolean', 'content': 'true' if value else 'false'}
            else:
                content = str(value) if value is not None else 'null'
                return {'type': 'literal', 'content': content}
        
        # Identifier
        elif arg_type == 'Identifier':
            name = arg.get('name', 'unknown')
            return {'type': 'variable', 'content': name}
        
        # Template literal - Full concatenation, no simplification
        elif arg_type == 'TemplateLiteral':
            return self._extract_template_literal_content(arg)
        
        # Function call
        elif arg_type == 'CallExpression':
            call_analysis = self._analyze_call_structure(arg)
            return {'type': 'function_call', 'content': call_analysis['name']}
        
        # Object expression - Full concatenation
        elif arg_type == 'ObjectExpression':
            return self._extract_object_expression_content(arg)
        
        # Array expression - Full concatenation
        elif arg_type == 'ArrayExpression':
            return self._extract_array_expression_content(arg)
        
        # Member access
        elif arg_type == 'MemberExpression':
            return self._extract_member_expression_content(arg)
        
        # Binary expression
        elif arg_type == 'BinaryExpression':
            return self._extract_binary_expression_content(arg)
        
        # Update expression
        elif arg_type == 'UpdateExpression':
            return self._extract_update_expression_content(arg)
        
        # RegExp literal
        elif arg_type == 'RegExpLiteral':
            pattern = arg.get('pattern', '')
            flags = arg.get('flags', '')
            return {'type': 'regex', 'content': f"/{pattern}/{flags}"}
        
        # Other types
        else:
            return {'type': 'unknown', 'content': arg_type}
    
    def _extract_template_literal_content(self, template: Dict) -> Dict:
        """Extract template literal content - Keep original content fully"""
        quasis = template.get('quasis', [])
        expressions = template.get('expressions', [])
        
        # Full concatenation of template literal, no simplification
        template_parts = []
        expr_index = 0
        
        for i, quasi in enumerate(quasis):
            raw_value = quasi.get('value', {}).get('raw', '')
            template_parts.append(raw_value)
            
            if expr_index < len(expressions):
                expr = expressions[expr_index]
                expr_content = self._extract_expression_for_template(expr)
                template_parts.append(f"${{{expr_content}}}")
                expr_index += 1
        
        full_content = ''.join(template_parts)
        
        return {'type': 'template', 'content': full_content}
    
    def _extract_expression_for_template(self, expr: Dict) -> str:
        """Extract expression content for template literal - Direct concatenation"""
        if expr is None:  # Add None check
            return 'unknown'
            
        expr_type = expr.get('type')
        
        if expr_type == 'Identifier':
            return expr.get('name', 'unknown')
        elif expr_type == 'UpdateExpression':
            operator = expr.get('operator', '')
            argument_node = expr.get('argument', {})
            if argument_node is not None:  # Add None check
                argument = self._extract_expression_for_template(argument_node)
            else:
                argument = 'unknown'
            prefix = expr.get('prefix', True)
            return f"{operator}{argument}" if prefix else f"{argument}{operator}"
        elif expr_type in ['Literal', 'StringLiteral', 'NumericLiteral']:
            value = expr.get('value')
            return f'"{value}"' if isinstance(value, str) else str(value)
        elif expr_type == 'BooleanLiteral':
            value = expr.get('value')
            return 'true' if value else 'false'
        elif expr_type == 'CallExpression':
            call_analysis = self._analyze_call_structure(expr)
            args = expr.get('arguments', [])
            arg_contents = []
            for arg in args:
                if arg is not None:  # Add None check
                    arg_contents.append(self._extract_expression_for_template(arg))
            return f"{call_analysis['name']}({', '.join(arg_contents)})"
        elif expr_type == 'MemberExpression':
            obj_node = expr.get('object', {})
            prop_node = expr.get('property', {})
            
            if obj_node is not None:  # Add None check
                obj = self._extract_expression_for_template(obj_node)
            else:
                obj = 'unknown'
                
            if prop_node is not None:  # Add None check
                prop = prop_node.get('name', 'unknown')
            else:
                prop = 'unknown'
                
            computed = expr.get('computed', False)
            return f"{obj}[{prop}]" if computed else f"{obj}.{prop}"
        elif expr_type == 'BinaryExpression':
            left_node = expr.get('left', {})
            right_node = expr.get('right', {})
            
            if left_node is not None:  # Add None check
                left = self._extract_expression_for_template(left_node)
            else:
                left = 'unknown'
                
            if right_node is not None:  # Add None check
                right = self._extract_expression_for_template(right_node)
            else:
                right = 'unknown'
                
            operator = expr.get('operator', '')
            return f"{left} {operator} {right}"
        else:
            return expr_type if expr_type else 'unknown'
    def _extract_object_expression_content(self, obj_expr: Dict) -> Dict:
        """Extract object expression content - Full concatenation"""
        properties = obj_expr.get('properties', [])
        
        if not properties:
            return {'type': 'object', 'content': '{}'}
        
        # Full concatenation of all properties
        prop_strings = []
        for prop in properties:
            if prop.get('type') in ['Property', 'ObjectProperty']:
                key = self._extract_property_key(prop)
                value = self._extract_property_value(prop)
                prop_strings.append(f"{key}: {value}")
        
        obj_content = "{" + ", ".join(prop_strings) + "}"
        return {'type': 'object', 'content': obj_content}
    
    def _extract_property_key(self, prop: Dict) -> str:
        """Extract object property key - Return string directly"""
        key = prop.get('key', {})
        key_type = key.get('type')
        
        if key_type == 'Identifier':
            return key.get('name', 'unknown')
        elif key_type in ['Literal', 'StringLiteral']:
            value = key.get('value')
            return f'"{value}"' if isinstance(value, str) else str(value)
        else:
            return 'unknown'
    
    def _extract_property_value(self, prop: Dict) -> str:
        """Extract object property value - Keep original boolean values"""
        value = prop.get('value', {})
        
        # Special handling for boolean values
        if value.get('type') == 'BooleanLiteral':
            bool_value = value.get('value')
            return 'true' if bool_value else 'false'
        
        value_content = self._extract_argument_content(value)
        return value_content['content']
    
    def _extract_array_expression_content(self, arr_expr: Dict) -> Dict:
        """Extract array expression content - Full content extraction"""
        elements = arr_expr.get('elements', [])
        
        if not elements:
            return {'type': 'array', 'content': '[]'}
        
        # Recursively process each element to get specific content
        elem_strings = []
        for elem in elements:
            if elem is None:
                elem_strings.append('null')
            else:
                # Recursively call to get element specific content
                elem_content = self._extract_argument_content(elem)
                elem_strings.append(elem_content['content'])
        
        # Concatenate full array content
        arr_content = "[" + ", ".join(elem_strings) + "]"
        return {'type': 'array', 'content': arr_content}
    def _extract_member_expression_content(self, member_expr: Dict) -> Dict:
        """Extract member expression content - Full concatenation"""
        obj = member_expr.get('object', {})
        prop = member_expr.get('property', {})
        computed = member_expr.get('computed', False)
        
        obj_content = self._extract_argument_content(obj)
        prop_content = self._extract_argument_content(prop)
        
        if computed:
            full_content = f"{obj_content['content']}[{prop_content['content']}]"
        else:
            full_content = f"{obj_content['content']}.{prop_content['content']}"
        
        return {'type': 'member_access', 'content': full_content}
    
    def _extract_binary_expression_content(self, binary_expr: Dict) -> Dict:
        """Extract binary expression content - Full concatenation"""
        left = binary_expr.get('left', {})
        right = binary_expr.get('right', {})
        operator = binary_expr.get('operator', '?')
        
        left_content = self._extract_argument_content(left)
        right_content = self._extract_argument_content(right)
        
        full_content = f"{left_content['content']} {operator} {right_content['content']}"
        return {'type': 'binary_expression', 'content': full_content}
    
    def _extract_update_expression_content(self, update_expr: Dict) -> Dict:
        """Extract update expression content - Full concatenation"""
        argument = update_expr.get('argument', {})
        operator = update_expr.get('operator', '++')
        prefix = update_expr.get('prefix', True)
        
        arg_content = self._extract_argument_content(argument)
        
        if prefix:
            full_content = f"{operator}{arg_content['content']}"
        else:
            full_content = f"{arg_content['content']}{operator}"
        
        return {'type': 'update_expression', 'content': full_content}
    
    def _handle_function_declaration(self, ast_node: Dict, parent_id: str, context: str):
        """Process function declaration"""
        # Fix here: Correctly handle id as None
        id_node = ast_node.get('id')
        if id_node is not None:
            func_name = id_node.get('name', 'anonymous')
        else:
            func_name = 'anonymous'
        
        func_id = self._create_node(
            'FUNCTION_DEF',
            'function_def',
            function_name=func_name,
            is_async=ast_node.get('async', False),
            is_generator=ast_node.get('generator', False)
        )
        
        # Added: Record function definition to symbol table
        if func_name != 'anonymous':
            self.function_definitions[func_name] = func_id
            print(f"  Function definition recorded: {func_name} -> {func_id}")
        
        self._add_edge(parent_id, func_id, 'defines')
        self._handle_function_parameters(ast_node.get('params', []), func_id)
        
        body = ast_node.get('body')
        if body is not None:  # Add None check
            self._enqueue_function_body(body, func_id)
    def _handle_class_declaration(self, ast_node: Dict, parent_id: str, context: str):
        """Process class declaration"""
        # Add None check
        id_node = ast_node.get('id')
        if id_node is not None:
            class_name = id_node.get('name', 'anonymous')
        else:
            class_name = 'anonymous'
        
        class_id = self._create_node(
            'CLASS',
            'class',
            class_name=class_name
        )
        
        self._add_edge(parent_id, class_id, 'defines')
        
        class_body = ast_node.get('body', {})
        if class_body and class_body.get('type') == 'ClassBody':
            methods = class_body.get('body', [])
            for method in methods:
                if method is not None:  # Add None check
                    self._enqueue_child(method, class_id, 'class_member')
    def _handle_function_expression(self, ast_node: Dict, parent_id: str, context: str):
        """Process function expression"""
        is_callback = context in ['call_argument', 'array_element', 'object_property']
        
        func_id = self._create_node(
            'ANONYMOUS_FUNCTION',
            'anonymous_function',
            is_callback=is_callback,
            is_async=ast_node.get('async', False)
        )
        
        edge_type = 'callback' if is_callback else 'defines'
        self._add_edge(parent_id, func_id, edge_type)
        
        self._handle_function_parameters(ast_node.get('params', []), func_id)
        
        body = ast_node.get('body')
        if body:
            self._enqueue_function_body(body, func_id)
    
    def _handle_new_expression(self, ast_node: Dict, parent_id: str, context: str):
        """Process new expression"""
        constructor_name = self._extract_constructor_name(ast_node)
        
        call_id = self._create_node(
            'CALL',
            'call',
            callee_name=f"new {constructor_name}",
            is_constructor=True
        )
        
        edge_type = 'calls' if context in ['top_level', 'function_body'] else 'nested_in'
        self._add_edge(parent_id, call_id, edge_type)
        
        self._handle_call_arguments(ast_node.get('arguments', []), call_id)
    
    def _handle_variable_declaration(self, ast_node: Dict, parent_id: str, context: str):
        """Process variable declaration"""
        for declarator in ast_node.get('declarations', []):
            if declarator is not None and declarator.get('init') is not None:  # Add None check
                self._enqueue_child(declarator['init'], parent_id, 'variable_init')
    def _handle_expression_statement(self, ast_node: Dict, parent_id: str, context: str):
        """Process expression statement"""
        expression = ast_node.get('expression')
        if expression is not None:  # Add None check
            self._enqueue_child(expression, parent_id, context)
    def _handle_control_flow(self, ast_node: Dict, parent_id: str, context: str):
        """Process control flow statements"""
        node_type = ast_node.get('type')
        
        if node_type == 'IfStatement':
            test_node = ast_node.get('test')
            if test_node is not None:  # Add None check
                self._enqueue_child(test_node, parent_id, 'condition')
                
            consequent_node = ast_node.get('consequent')
            if consequent_node is not None:  # Add None check
                self._enqueue_child(consequent_node, parent_id, 'branch')
                
            alternate_node = ast_node.get('alternate')
            if alternate_node is not None:  # Add None check
                self._enqueue_child(alternate_node, parent_id, 'branch')
        
        elif node_type == 'ForStatement':
            for field in ['init', 'test', 'update', 'body']:
                field_node = ast_node.get(field)
                if field_node is not None:  # Add None check
                    context_map = {
                        'init': 'loop_init',
                        'test': 'loop_condition', 
                        'update': 'loop_update',
                        'body': 'loop_body'
                    }
                    self._enqueue_child(field_node, parent_id, context_map[field])
        
        elif node_type == 'WhileStatement':
            test_node = ast_node.get('test')
            if test_node is not None:  # Add None check
                self._enqueue_child(test_node, parent_id, 'loop_condition')
                
            body_node = ast_node.get('body')
            if body_node is not None:  # Add None check
                self._enqueue_child(body_node, parent_id, 'loop_body')
        
        elif node_type == 'BlockStatement':
            body_nodes = ast_node.get('body', [])
            for stmt in body_nodes:
                if stmt is not None:  # Add None check
                    self._enqueue_child(stmt, parent_id, 'function_body')
    def _handle_generic_node(self, ast_node: Dict, parent_id: str, context: str):
        """Process generic node"""
        if ast_node is None:  # Add None check
            return
            
        for key, value in ast_node.items():
            if key in ['loc', 'start', 'end', 'range', 'comments']:
                continue
            
            if isinstance(value, list):
                for item in value:
                    if item is not None and isinstance(item, dict) and item.get('type'):  # Add None check
                        self._enqueue_child(item, parent_id, context)
            
            elif value is not None and isinstance(value, dict) and value.get('type'):  # Add None check
                self._enqueue_child(value, parent_id, context)
    def _handle_function_parameters(self, params: List[Dict], func_id: str):
        """Process function parameters"""
        if not params:  # Add None check
            return
            
        for param in params:
            if param is not None:  # Add None check
                param_name = self._extract_parameter_name(param)
                
                param_id = self._create_node(
                    'PARAMETER',
                    'parameter',
                    parameter_name=param_name
                )
                
                self._add_edge(func_id, param_id, 'has_param')
    def _enqueue_function_body(self, body: Dict, func_id: str):
        """Add function body to queue"""
        if body is None:  # Add None check
            return
            
        if body.get('type') == 'BlockStatement':
            body_statements = body.get('body', [])
            for stmt in body_statements:
                if stmt is not None:  # Add None check
                    self._enqueue_child(stmt, func_id, 'function_body')
        else:
            self._enqueue_child(body, func_id, 'function_body')
    def _enqueue_child(self, child_node: Dict, parent_id: str, context: str):
        """Add child node to queue"""
        if child_node is not None and child_node.get('type'):  # Add None check
            self.processing_queue.append({
                'ast_node': child_node,
                'parent_id': parent_id,
                'context': context
            })
    def _create_node(self, node_type: str, label: str, **attributes) -> str:
        """Create node"""
        node_id = f"n{self.node_id_counter}"
        self.node_id_counter += 1
        
        node = {
            'id': node_id,
            'type': node_type,
            'label': label,
            **attributes
        }
        
        self.nodes.append(node)
        return node_id
    
    def _add_edge(self, source: str, target: str, edge_type: str):
        """Add edge"""
        edge_exists = any(
            e['source'] == source and e['target'] == target and e['type'] == edge_type
            for e in self.edges
        )
        
        if not edge_exists:
            self.edges.append({
                'source': source,
                'target': target,
                'type': edge_type
            })
    
    def _extract_expression_name(self, expr: Dict) -> str:
        """Extract expression name"""
        if expr is None:  # Add None check
            return 'unknown'
        
        expr_type = expr.get('type')
        
        if expr_type == 'Identifier':
            return expr.get('name', 'unknown')
        elif expr_type == 'MemberExpression':
            obj = expr.get('object', {})
            prop = expr.get('property', {})
            
            obj_name = self._extract_expression_name(obj) if obj is not None else 'unknown'
            prop_name = prop.get('name', 'unknown') if prop is not None else 'unknown'
            
            return f"{obj_name}.{prop_name}"
        elif expr_type == 'ThisExpression':
            return 'this'
        else:
            return expr_type.lower()
    def _extract_constructor_name(self, ast_node: Dict) -> str:
        """Extract constructor name"""
        callee = ast_node.get('callee', {})
        return self._extract_expression_name(callee)
    
    def _extract_parameter_name(self, param: Dict) -> str:
        """Extract parameter name"""
        if param.get('type') == 'Identifier':
            return param.get('name', 'unknown')
        elif param.get('type') == 'ObjectPattern':
            return '{...}'
        elif param.get('type') == 'ArrayPattern':
            return '[...]'
        else:
            return param.get('type', 'unknown')
    
    def _validate_and_generate_stats(self) -> Dict:
        """Validate graph structure and generate statistics"""
        validation = self._validate_tree_structure()
        stats = self._generate_statistics()
        
        return {
            'nodes': self.nodes,
            'edges': self.edges,
            'validation': validation,
            'statistics': stats,
            'call_analysis': self._generate_call_analysis(),
            'summary': {
                'node_count': len(self.nodes),
                'edge_count': len(self.edges),
                'is_valid_tree': validation.get('is_valid_tree', False),
                'has_calls': any(e['type'] == 'chained_call' for e in self.edges)
            }
        }
    
    def _validate_tree_structure(self) -> Dict:
        """Validate tree structure"""
        validation = {
            'is_valid_tree': True,
            'errors': [],
            'warnings': []
        }
        
        # Check in-degree
        in_degrees = defaultdict(int)
        for edge in self.edges:
            in_degrees[edge['target']] += 1
        
        # Find root nodes
        root_nodes = []
        for node in self.nodes:
            if in_degrees[node['id']] == 0:
                root_nodes.append(node)
        
        # Only FILE type should be root node
        actual_roots = [node for node in root_nodes if node['type'] == 'FILE']
        
        if len(actual_roots) != 1:
            validation['is_valid_tree'] = False
            validation['errors'].append(f"Expected 1 FILE root node, found {len(actual_roots)}")
        
        validation['root_nodes'] = actual_roots
        
        return validation
    
    def _generate_statistics(self) -> Dict:
        """Generate statistics"""
        stats = {
            'node_types': defaultdict(int),
            'edge_types': defaultdict(int),
            'function_count': 0,
            'call_count': 0,
            'class_count': 0,
            'chained_call_count': 0
        }
        
        for node in self.nodes:
            stats['node_types'][node['type']] += 1
            
            if node['type'] in ['FUNCTION_DEF', 'ANONYMOUS_FUNCTION']:
                stats['function_count'] += 1
            elif node['type'] == 'CALL':
                stats['call_count'] += 1
                if node.get('is_chained', False):
                    stats['chained_call_count'] += 1
            elif node['type'] == 'CLASS':
                stats['class_count'] += 1
        
        for edge in self.edges:
            stats['edge_types'][edge['type']] += 1
        
        return dict(stats)
    
    def _generate_call_analysis(self) -> Dict:
        """Generate call analysis"""
        chained_calls = sum(1 for edge in self.edges if edge['type'] == 'chained_call')
        base_calls = len(set(edge['source'] for edge in self.edges if edge['type'] == 'chained_call'))
        
        return {
            'total_calls': chained_calls,
            'base_calls': base_calls,
            'call_details': {}
        }
    
    def save_pdcg(self, result: Dict, output_path: str):
        """Save PDCG data"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"PDCG analysis result saved to: {output_path}")
        except Exception as e:
            print(f"Save failed: {e}")

    def print_single_file_summary(result: Dict):
        """Print single file processing summary"""
        print(f"\nPDCG Analysis Result Summary:")
        print(f"   Node count: {result['summary']['node_count']}")
        print(f"   Edge count: {result['summary']['edge_count']}")
        print(f"   Chained call count: {result['call_analysis']['total_calls']}")
        print(f"   Base call count: {result['call_analysis']['base_calls']}")
        print(f"   Is tree: {result['summary']['is_valid_tree']}")
    
    def validate_directories(ast_root: str, pdcg_root: str) -> bool:
        """Validate directory structure"""
        if not os.path.exists(ast_root):
            print(f"Error: AST root directory does not exist: {ast_root}")
            return False
        
        # Create PDCG root directory if it does not exist
        try:
            os.makedirs(pdcg_root, exist_ok=True)
            print(f"PDCG root directory ready: {pdcg_root}")
        except Exception as e:
            print(f"Error: Unable to create PDCG root directory: {e}")
            return False
        
        return True
class DirectPDCGProcessor:
    """Direct PDCG Processor - Process AST files with arbitrary directory structure"""
    
    def __init__(self, input_dir: str, output_dir: str):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.processed_count = 0
        self.failed_count = 0
        self.start_time = None
        
        # Failure tracking
        self.failed_files = []
        
    def process_direct(self, skip_existing: bool = False):
        """Direct processing mode - Process all AST files in input directory"""
        print(f"Starting direct PDCG processing")
        print(f"  Input directory: {self.input_dir}")
        print(f"  Output directory: {self.output_dir}")
        print(f"  Skip existing: {skip_existing}")
        
        if not os.path.exists(self.input_dir):
            print(f"Error: Input directory does not exist: {self.input_dir}")
            return
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Collect all AST files
        ast_files = self._collect_ast_files()
        if not ast_files:
            print("No AST files found")
            return
        
        print(f"Found {len(ast_files)} AST files")
        
        self.start_time = time.time()
        
        # Process each AST file
        for i, ast_file in enumerate(ast_files, 1):
            self._process_single_ast_direct(ast_file, i, len(ast_files), skip_existing)
        
        self._print_direct_summary()
    
    def _collect_ast_files(self) -> List[str]:
        """Collect all AST files"""
        ast_files = []
        
        for root, dirs, files in os.walk(self.input_dir):
            for file in files:
                if file.endswith('.ast.json'):
                    ast_files.append(os.path.join(root, file))
        
        return sorted(ast_files)
    
    def _process_single_ast_direct(self, ast_file: str, current: int, total: int, skip_existing: bool):
        """Process single AST file"""
        # Calculate relative path and build output path
        rel_path = os.path.relpath(ast_file, self.input_dir)
        pdcg_file = os.path.join(self.output_dir, rel_path.replace('.ast.json', '.pdcg.json'))
        
        # Create output directory
        os.makedirs(os.path.dirname(pdcg_file), exist_ok=True)
        
        # Check if skip existing files
        if skip_existing and os.path.exists(pdcg_file):
            print(f"[{current}/{total}] Skipped (exists): {os.path.basename(ast_file)}")
            return
        
        try:
            print(f"[{current}/{total}] Processing: {os.path.basename(ast_file)}")
            
            # Analyze AST
            analyzer = PDCGAnalyzer()
            result = analyzer.analyze_pdcg_from_ast(ast_file)
            
            if 'error' in result:
                self._record_failure_direct(ast_file, pdcg_file, result['error'])
                return
            
            # Save PDCG
            analyzer.save_pdcg(result, pdcg_file)
            self.processed_count += 1
            
        except Exception as e:
            self._record_failure_direct(ast_file, pdcg_file, str(e))
    
    def _record_failure_direct(self, ast_file: str, pdcg_file: str, error_message: str):
        """Record failure information"""
        self.failed_count += 1
        self.failed_files.append({
            'ast_file': ast_file,
            'pdcg_file': pdcg_file,
            'error': error_message,
            'timestamp': time.time()
        })
        print(f"  Failed: {error_message}")
    
    def _print_direct_summary(self):
        """Print processing summary"""
        elapsed = time.time() - self.start_time
        total_files = self.processed_count + self.failed_count
        
        print(f"\n=== Direct Processing Complete ===")
        print(f"Total files: {total_files}")
        print(f"Successfully processed: {self.processed_count}")
        print(f"Failed: {self.failed_count}")
        print(f"Success rate: {(self.processed_count/total_files*100):.1f}%" if total_files > 0 else "Success rate: 0%")
        print(f"Total time: {elapsed:.2f}s")
        print(f"Average speed: {(total_files/elapsed):.2f} files/s" if elapsed > 0 else "Average speed: N/A")
        
        if self.failed_files:
            print(f"\nFailed files list:")
            for failure in self.failed_files[:10]:  # Only show top 10
                print(f"  - {os.path.basename(failure['ast_file'])}: {failure['error']}")
            if len(self.failed_files) > 10:
                print(f"  ... {len(self.failed_files) - 10} more failed files")


class BatchPDCGProcessor:
    """Batch PDCG Processor"""
    
    def __init__(self, ast_root: str, pdcg_root: str):
        self.ast_root = ast_root
        self.pdcg_root = pdcg_root
        self.processed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.start_time = None
        
        # Detailed failure tracking
        self.failed_files = []  # Store detailed information of failed files
        self.failure_categories = {
            'ast_load_error': [],
            'ast_parse_error': [],
            'pdcg_generation_error': [],
            'file_save_error': [],
            'permission_error': [],
            'unknown_error': []
        }
    def process_batch(self, data_type: str = 'both', limit: int = -1, 
                     target_packages: List[str] = None, skip_existing: bool = False,
                     generate_report: bool = True):
        """Batch process AST files"""
        print(f"Starting batch PDCG processing")
        print(f"  AST root directory: {self.ast_root}")
        print(f"  PDCG root directory: {self.pdcg_root}")
        print(f"  Data type: {data_type}")
        print(f"  Processing limit: {limit if limit > 0 else 'unlimited'}")
        print(f"  Target packages: {target_packages if target_packages else 'all'}")
        print(f"  Skip existing: {skip_existing}")
        print(f"  Generate failure report: {generate_report}")
        
        self.start_time = time.time()
        
        # Get processing targets
        targets = self._get_processing_targets(data_type, target_packages, limit)
        
        if not targets:
            print("No AST files found to process")
            return
        
        print(f"Found {len(targets)} AST files to process")
        
        # Process each AST file
        for i, (ast_file, pdcg_file) in enumerate(targets, 1):
            if skip_existing and os.path.exists(pdcg_file):
                print(f"[{i}/{len(targets)}] Skipped (exists): {os.path.basename(ast_file)}")
                self.skipped_count += 1
                continue
            
            self._process_single_ast(ast_file, pdcg_file, i, len(targets))
        
        # Output summary
        self._print_batch_summary(len(targets))
        
        # Generate failure report
        if generate_report and self.failed_files:
            self.generate_failure_report()
    def _get_processing_targets(self, data_type: str, target_packages: List[str], 
                               limit: int) -> List[tuple]:
        """Get processing target list"""
        targets = []
        
        # Determine data type directories to process
        data_dirs = []
        if data_type in ['both', 'benign']:
            benign_dir = os.path.join(self.ast_root, 'benign')
            if os.path.exists(benign_dir):
                data_dirs.append(('benign', benign_dir))
        
        if data_type in ['both', 'malicious']:
            malicious_dir = os.path.join(self.ast_root, 'malicious')
            if os.path.exists(malicious_dir):
                data_dirs.append(('malicious', malicious_dir))
        
        # Iterate each data type directory
        for data_type_name, data_dir in data_dirs:
            package_dirs = [d for d in os.listdir(data_dir) 
                           if os.path.isdir(os.path.join(data_dir, d))]
            
            # Filter specified package names
            if target_packages:
                package_dirs = [d for d in package_dirs if d in target_packages]
            
            # Iterate each package directory
            for package_name in package_dirs:
                package_path = os.path.join(data_dir, package_name)
                ast_files = self._find_ast_files(package_path)
                
                for ast_file in ast_files:
                    # Calculate corresponding PDCG file path, replace .ast.json with .pdcg.json
                    rel_path = os.path.relpath(ast_file, self.ast_root)
                    
                    # Replace file suffix: .ast.json -> .pdcg.json
                    if rel_path.endswith('.ast.json'):
                        pdcg_rel_path = rel_path[:-9] + '.pdcg.json'  # Remove '.ast.json', add '.pdcg.json'
                    else:
                        # If not ending with .ast.json, directly add .pdcg.json
                        pdcg_rel_path = rel_path + '.pdcg.json'
                    
                    pdcg_file = os.path.join(self.pdcg_root, pdcg_rel_path)
                    
                    targets.append((ast_file, pdcg_file))
                    
                    # Check limit
                    if limit > 0 and len(targets) >= limit:
                        return targets
        
        return targets
    def _find_ast_files(self, package_path: str) -> List[str]:
        """Find all AST files in package directory"""
        ast_files = []
        
        for root, dirs, files in os.walk(package_path):
            for file in files:
                if file.endswith('.ast.json'):
                    ast_files.append(os.path.join(root, file))
        
        return sorted(ast_files)
    
    def _process_single_ast(self, ast_file: str, pdcg_file: str, current: int, total: int):
        """Process single AST file"""
        package_name = self._extract_package_name(ast_file)
        file_name = os.path.basename(ast_file)
        
        try:
            print(f"[{current}/{total}] Processing: {package_name}/{file_name}")
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(pdcg_file), exist_ok=True)
            
            # Create analyzer - modified here, no parameters passed
            analyzer = PDCGAnalyzer()
            
            # Attempt analysis
            result = analyzer.analyze_pdcg_from_ast(ast_file)
            
            if 'error' in result:
                # PDCG generation failed
                error_msg = result['error']
                print(f"  ❌ Analysis failed: {error_msg}")
                
                self._record_failure(
                    ast_file=ast_file,
                    pdcg_file=pdcg_file,
                    package_name=package_name,
                    file_name=file_name,
                    error_type='pdcg_generation_error',
                    error_message=error_msg,
                    stage='PDCG Generation'
                )
                return
            
            # Attempt to save result
            try:
                analyzer.save_pdcg(result, pdcg_file)
            except PermissionError as e:
                self._record_failure(
                    ast_file=ast_file,
                    pdcg_file=pdcg_file,
                    package_name=package_name,
                    file_name=file_name,
                    error_type='permission_error',
                    error_message=f"Permission error: {str(e)}",
                    stage='File Save'
                )
                return
            except OSError as e:
                self._record_failure(
                    ast_file=ast_file,
                    pdcg_file=pdcg_file,
                    package_name=package_name,
                    file_name=file_name,
                    error_type='file_save_error',
                    error_message=f"File save error: {str(e)}",
                    stage='File Save'
                )
                return
            
            # Successfully processed
            node_count = result['summary']['node_count']
            edge_count = result['summary']['edge_count']
            print(f"  ✅ Success: {node_count} nodes, {edge_count} edges")
            
            self.processed_count += 1
            
        except FileNotFoundError as e:
            self._record_failure(
                ast_file=ast_file,
                pdcg_file=pdcg_file,
                package_name=package_name,
                file_name=file_name,
                error_type='ast_load_error',
                error_message=f"AST file does not exist: {str(e)}",
                stage='AST Load'
            )
            
        except json.JSONDecodeError as e:
            self._record_failure(
                ast_file=ast_file,
                pdcg_file=pdcg_file,
                package_name=package_name,
                file_name=file_name,
                error_type='ast_parse_error',
                error_message=f"AST parse error: {str(e)}",
                stage='AST Parse'
            )
            
        except Exception as e:
            self._record_failure(
                ast_file=ast_file,
                pdcg_file=pdcg_file,
                package_name=package_name,
                file_name=file_name,
                error_type='unknown_error',
                error_message=f"Unknown error: {str(e)}",
                stage='Unknown'
            )
    def _record_failure(self, ast_file: str, pdcg_file: str, package_name: str, 
                       file_name: str, error_type: str, error_message: str, stage: str):
        """Record failure details"""
        failure_info = {
            'package_name': package_name,
            'file_name': file_name,
            'ast_file': ast_file,
            'pdcg_file': pdcg_file,
            'error_type': error_type,
            'error_message': error_message,
            'failure_stage': stage,
            'timestamp': time.time()
        }
        
        # Add to total failure list
        self.failed_files.append(failure_info)
        
        # Classify by category
        if error_type in self.failure_categories:
            self.failure_categories[error_type].append(failure_info)
        
        self.failed_count += 1
    def generate_failure_report(self, output_dir: str = None):
        """Generate detailed failure report"""
        if not self.failed_files:
            print("No failed files, no failure report needed")
            return
        
        # Determine output directory
        if output_dir is None:
            output_dir = os.path.dirname(self.pdcg_root)
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate text report
        report_file = os.path.join(output_dir, "pdcg_failure_report.txt")
        self._generate_text_report(report_file)
        
        # Generate CSV report
        csv_file = os.path.join(output_dir, "pdcg_failure_details.csv")
        self._generate_csv_report(csv_file)
        
        print(f"\nFailure report generated:")
        print(f"  Detailed report: {report_file}")
        print(f"  CSV file: {csv_file}")
    
    def _generate_text_report(self, report_file: str):
        """Generate text format failure report"""
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("PDCG Generation Failure Detailed Report\n")
            f.write("="*80 + "\n")
            f.write(f"Generation time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total failed files: {len(self.failed_files)}\n\n")
            
            # Classify statistics by error type
            f.write("1. Failure Type Statistics\n")
            f.write("-"*40 + "\n")
            for error_type, failures in self.failure_categories.items():
                if failures:
                    f.write(f"{error_type}: {len(failures)} files\n")
            f.write("\n")
            
            # Group statistics by package name
            package_failures = {}
            for failure in self.failed_files:
                pkg = failure['package_name']
                if pkg not in package_failures:
                    package_failures[pkg] = []
                package_failures[pkg].append(failure)
            
            f.write("2. Failure Statistics Grouped by Package Name\n")
            f.write("-"*40 + "\n")
            for pkg_name, pkg_failures in sorted(package_failures.items()):
                f.write(f"{pkg_name}: {len(pkg_failures)} files failed\n")
            f.write("\n")
            
            # Detailed failure information
            f.write("3. Detailed Failure Information\n")
            f.write("-"*40 + "\n")
            
            for i, failure in enumerate(self.failed_files, 1):
                f.write(f"\nFailure #{i}:\n")
                f.write(f"  Package: {failure['package_name']}\n")
                f.write(f"  File: {failure['file_name']}\n")
                f.write(f"  AST path: {failure['ast_file']}\n")
                f.write(f"  Error type: {failure['error_type']}\n")
                f.write(f"  Failure stage: {failure['failure_stage']}\n")
                f.write(f"  Error message: {failure['error_message']}\n")
                f.write(f"  Timestamp: {time.strftime('%H:%M:%S', time.localtime(failure['timestamp']))}\n")
            
            # Error type detailed analysis
            f.write("\n\n4. Error Type Detailed Analysis\n")
            f.write("="*40 + "\n")
            
            for error_type, failures in self.failure_categories.items():
                if not failures:
                    continue
                    
                f.write(f"\n{error_type.upper()} ({len(failures)} files):\n")
                f.write("-"*30 + "\n")
                
                # Display grouped by package name
                type_packages = {}
                for failure in failures:
                    pkg = failure['package_name']
                    if pkg not in type_packages:
                        type_packages[pkg] = []
                    type_packages[pkg].append(failure['file_name'])
                
                for pkg_name, file_names in sorted(type_packages.items()):
                    f.write(f"  {pkg_name}:\n")
                    for file_name in sorted(file_names):
                        f.write(f"    - {file_name}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("Report End\n")
            f.write("="*80 + "\n")
    
    def _generate_csv_report(self, csv_file: str):
        """Generate CSV format failure report"""
        import pandas as pd
        
        if not self.failed_files:
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(self.failed_files)
        
        # Add timestamp conversion
        df['formatted_time'] = df['timestamp'].apply(
            lambda x: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(x))
        )
        
        # Rearrange columns
        columns_order = [
            'package_name', 'file_name', 'error_type', 'failure_stage',
            'error_message', 'formatted_time', 'ast_file', 'pdcg_file'
        ]
        
        df = df[columns_order]
        
        # Save CSV
        df.to_csv(csv_file, index=False, encoding='utf-8')
    def _extract_package_name(self, ast_file: str) -> str:
        """Extract package name from AST file path"""
        # Extract package name from path
        # .../malicious/package_name/... -> package_name
        parts = ast_file.replace('\\', '/').split('/')
        
        for i, part in enumerate(parts):
            if part in ['benign', 'malicious']:
                if i + 1 < len(parts):
                    return parts[i + 1]
        
        return 'unknown_package'
    
    def _print_batch_summary(self, total_targets: int):
        """Print batch processing summary"""
        elapsed_time = time.time() - self.start_time
        
        print(f"\n" + "="*80)
        print(f"Batch PDCG processing complete!")
        print(f"="*80)
        print(f"  Total targets: {total_targets}")
        print(f"  Successfully processed: {self.processed_count}")
        print(f"  Failed: {self.failed_count}")
        print(f"  Skipped files: {self.skipped_count}")
        print(f"  Processing time: {elapsed_time:.2f} s")
        
        if self.processed_count > 0:
            avg_time = elapsed_time / self.processed_count
            print(f"  Average time: {avg_time:.2f} s/file")
        
        success_rate = (self.processed_count / total_targets * 100) if total_targets > 0 else 0
        print(f"  Success rate: {success_rate:.1f}%")
        
        # Failure detailed statistics
        if self.failed_files:
            print(f"\nFailure detailed statistics:")
            print("-"*40)
            
            for error_type, failures in self.failure_categories.items():
                if failures:
                    print(f"  {error_type}: {len(failures)} files")
            
            # Show packages with most failures
            package_failures = {}
            for failure in self.failed_files:
                pkg = failure['package_name']
                package_failures[pkg] = package_failures.get(pkg, 0) + 1
            
            if package_failures:
                print(f"\nTop 10 packages with most failures:")
                sorted_packages = sorted(package_failures.items(), key=lambda x: x[1], reverse=True)
                for pkg_name, count in sorted_packages[:10]:
                    print(f"    {pkg_name}: {count} files failed")
            
            # Show typical failure examples
            print(f"\nTypical failure examples:")
            for error_type, failures in self.failure_categories.items():
                if failures:
                    example = failures[0]
                    print(f"  {error_type}:")
                    print(f"    Package: {example['package_name']}")
                    print(f"    File: {example['file_name']}")
                    print(f"    Error: {example['error_message'][:100]}...")
                    break
        
        print(f"="*80)
def print_single_file_summary(result: Dict):
    """Print single file processing summary"""
    print(f"\nPDCG Analysis Result Summary:")
    print(f"   Node count: {result['summary']['node_count']}")
    print(f"   Edge count: {result['summary']['edge_count']}")
    print(f"   Chained call count: {result['call_analysis']['total_calls']}")
    print(f"   Base call count: {result['call_analysis']['base_calls']}")
    print(f"   Is tree: {result['summary']['is_valid_tree']}")

def validate_directories(ast_root: str, pdcg_root: str) -> bool:
    """Validate directory structure"""
    if not os.path.exists(ast_root):
        print(f"Error: AST root directory does not exist: {ast_root}")
        return False
    
    # Create PDCG root directory if it does not exist
    try:
        os.makedirs(pdcg_root, exist_ok=True)
        print(f"PDCG root directory ready: {pdcg_root}")
    except Exception as e:
        print(f"Error: Unable to create PDCG root directory: {e}")
        return False
    
    return True
def main():
    """Main function - Supports batch processing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PDCG Analyzer - Supports single file, batch and direct processing')
    parser.add_argument('--mode', choices=['single', 'batch', 'direct'], default='single', help='Processing mode: single(single file), batch(batch), direct(direct processing)')
    parser.add_argument('--input', type=str, help='Single file mode: AST file path; Batch mode: AST root directory path')
    parser.add_argument('--output', type=str, help='Single file mode: Output file path; Batch mode: PDCG root directory path')
    parser.add_argument('--input-dir', type=str, help='Direct mode: Input AST directory path')
    parser.add_argument('--output-dir', type=str, help='Direct mode: Output PDCG directory path')
    parser.add_argument('--type', choices=['benign', 'malicious', 'both'], default='both', help='Batch mode: Data type to process')
    parser.add_argument('--limit', type=int, default=-1, help='Batch mode: Limit number of packages to process (-1 for all)')
    parser.add_argument('--packages', nargs='*', help='Batch mode: Specify package name list')
    parser.add_argument('--skip-existing', action='store_true', help='Batch mode: Skip existing PDCG files')
    parser.add_argument('--no-report', action='store_true', help='Batch mode: Do not generate failure report')
    
    args = parser.parse_args()
    
    print("Starting PDCG analyzer")
    
    if args.mode == 'single':
        # Single file processing mode (kept unchanged)
        ast_file = args.input or r"..."
        output_file = args.output or r"..."
        
        if not os.path.exists(ast_file):
            print(f"AST file does not exist: {ast_file}")
            return
        
        analyzer = PDCGAnalyzer()
        result = analyzer.analyze_pdcg_from_ast(ast_file)
        
        if 'error' in result:
            print(f"Analysis failed: {result['error']}")
            return
        
        analyzer.save_pdcg(result, output_file)
        print_single_file_summary(result)
        
    elif args.mode == 'batch':
        # Batch processing mode
        ast_root = args.input or r"..."
        pdcg_root = args.output or r"..."
        
        if not os.path.exists(ast_root):
            print(f"AST root directory does not exist: {ast_root}")
            return
        
        batch_processor = BatchPDCGProcessor(ast_root, pdcg_root)
        batch_processor.process_batch(
            data_type=args.type,
            limit=args.limit,
            target_packages=args.packages,
            skip_existing=args.skip_existing,
            generate_report=not args.no_report
        )
    
    elif args.mode == 'direct':
        # Direct processing mode
        if not args.input_dir or not args.output_dir:
            print("Error: Direct mode requires --input-dir and --output-dir parameters")
            return
        
        if not os.path.exists(args.input_dir):
            print(f"Error: Input directory does not exist: {args.input_dir}")
            return
        
        print(f"Using direct processing mode")
        direct_processor = DirectPDCGProcessor(args.input_dir, args.output_dir)
        direct_processor.process_direct(skip_existing=args.skip_existing)
    
    print(f"\nPDCG analysis complete!")
if __name__ == "__main__":
    main()