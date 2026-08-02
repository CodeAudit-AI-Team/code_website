import ast
from typing import Dict, Any, List

class PythonASTParser(ast.NodeVisitor):
    """
    Parses Python source code into structured AST metadata
    including functions, classes, imports, call expressions, and unsafe constructs.
    """

    def __init__(self, code: str):
        self.code = code
        self.functions: List[Dict[str, Any]] = []
        self.classes: List[Dict[str, Any]] = []
        self.imports: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []
        self.assignments: List[Dict[str, Any]] = []
        self.exceptions: List[Dict[str, Any]] = []
        self.returns: List[Dict[str, Any]] = []
        self.variables: List[str] = []
        self.control_flow_count = 0
        self.is_valid = True
        self.error_message = ""

        try:
            self.tree = ast.parse(code)
            self.visit(self.tree)
        except Exception as e:
            self.is_valid = False
            self.error_message = str(e)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        args = [arg.arg for arg in node.args.args]
        self.functions.append({
            "name": node.name,
            "line": node.lineno,
            "args": args,
            "decorator_count": len(node.decorator_list)
        })
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
        self.classes.append({
            "name": node.name,
            "line": node.lineno,
            "bases": bases
        })
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append({
                "module": alias.name,
                "alias": alias.asname,
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            self.imports.append({
                "module": f"{module}.{alias.name}" if module else alias.name,
                "alias": alias.asname,
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        self.calls.append({
            "func_name": func_name,
            "line": node.lineno,
            "args_count": len(node.args),
            "kwargs_count": len(node.keywords)
        })
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
                if target.id not in self.variables:
                    self.variables.append(target.id)
        self.assignments.append({
            "targets": targets,
            "line": node.lineno
        })
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        self.exceptions.append({
            "line": node.lineno,
            "handlers": [h.type.id if isinstance(h.type, ast.Name) else "Exception" for h in node.handlers]
        })
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        self.returns.append({"line": node.lineno})
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        self.control_flow_count += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self.control_flow_count += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self.control_flow_count += 1
        self.generic_visit(node)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "valid": self.is_valid,
            "error": self.error_message,
            "total_functions": len(self.functions),
            "total_classes": len(self.classes),
            "total_imports": len(self.imports),
            "total_calls": len(self.calls),
            "total_variables": len(self.variables),
            "control_flow_statements": self.control_flow_count,
            "functions": self.functions,
            "classes": self.classes,
            "imports": self.imports
        }

    def get_ast_tree_str(self) -> str:
        if not self.is_valid:
            return f"Syntax Error: {self.error_message}"
        return ast.dump(self.tree, indent=2)
