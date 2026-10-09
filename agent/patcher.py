"""Bound the generated fixture patch before static scanning or execution."""
import ast
import difflib
from pathlib import Path

PATCHED = '''"""Vendored teaching fixture, version 1.0.1 (not a published package/CVE)."""
VERSION = "1.0.1"

def normalize_slug(value):
    normalized = value.strip().lower()
    if not normalized or "/" in normalized or "\\\\" in normalized:
        raise ValueError("slug must be a nonempty identifier without path separators")
    return normalized
'''

def validate_candidate(code):
    if not isinstance(code,str) or not 1<=len(code)<=4096: raise ValueError("invalid candidate size")
    tree=ast.parse(code)
    nodes=(ast.Module,ast.Expr,ast.Constant,ast.Assign,ast.Name,ast.Load,ast.Store,ast.FunctionDef,
        ast.arguments,ast.arg,ast.Return,ast.If,ast.Raise,ast.Call,ast.Attribute,ast.Compare,
        ast.In,ast.NotIn,ast.Eq,ast.NotEq,ast.BoolOp,ast.Or,ast.And,ast.UnaryOp,ast.Not)
    for n in ast.walk(tree):
        if not isinstance(n,nodes): raise ValueError("candidate contains unsupported syntax")
        if isinstance(n,ast.Attribute) and n.attr not in ("strip","lower"): raise ValueError("unsupported attribute")
        if isinstance(n,ast.Name) and (n.id.startswith('_') or n.id in ("eval","exec","open","globals","locals")): raise ValueError("unsupported name")
        if isinstance(n,ast.Call):
            if n.keywords or not ((isinstance(n.func,ast.Name) and n.func.id=="ValueError") or (isinstance(n.func,ast.Name) and n.func.id=="chr" and len(n.args)==1 and isinstance(n.args[0],ast.Constant) and n.args[0].value==92) or
                (isinstance(n.func,ast.Attribute) and n.func.attr in ("strip","lower") and not n.args)):
                raise ValueError("unsupported call")
    statements=[n for n in tree.body if not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str))]
    if len(statements)!=2 or not isinstance(statements[0],ast.Assign) or not isinstance(statements[1],ast.FunctionDef): raise ValueError("unexpected module structure")
    version,fun=statements
    if len(version.targets)!=1 or not isinstance(version.targets[0],ast.Name) or version.targets[0].id!="VERSION" or not isinstance(version.value,ast.Constant) or version.value.value!="1.0.1": raise ValueError("expected version bump")
    if fun.name!="normalize_slug" or fun.decorator_list or fun.returns or fun.args.defaults or fun.args.kw_defaults or fun.args.kwonlyargs or fun.args.posonlyargs or fun.args.vararg or fun.args.kwarg or len(fun.args.args)!=1 or fun.args.args[0].arg!="value" or fun.args.args[0].annotation: raise ValueError("unexpected function signature")
    if any(isinstance(n,ast.FunctionDef) and n is not fun for n in ast.walk(fun)): raise ValueError("nested function")
    return code.rstrip()+"\n"

def difference(before, after):
    return "".join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile="a/slug_dependency.py",tofile="b/slug_dependency.py"))

def patch(workspace, code=PATCHED):
    code=validate_candidate(code)
    target=Path(workspace)/"slug_dependency.py"
    before=target.read_text()
    target.write_text(code)
    return difference(before,code)
