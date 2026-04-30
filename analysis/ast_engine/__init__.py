from tree_sitter import Language, Parser
from dataclasses import dataclass
from typing import List
import tree_sitter_python as tspython

@dataclass
class ASTFinding:
    node_type: str
    description: str
    severity: str
    line: int

DANGER={"eval", "exec", "compiler", "__import__", "subprocess",
        "os.system", "pickle.loads", "marshal.loads",}

def scan_python(source: str)->List[ASTFinding]:
    py_lang=Language(tspython.language())
    parser=Parser(py_lang)
    tree=parser.parse(bytes(source, "utf-8"))
    findings=[]

    def walk(node):
        if node.type=="call":
            func=node.child_by_field_name(function)
            if func:
                name=source[func.start_byte:func.end_byte]
                if any(danger in name for danger in DANGER):
                    findings.append(ASTFinding(
                        node_type="dangerous_call",
                        description=f"Dangerous function call => {name}",
                        severity="HIGH",
                        line=node.start_point[0]
                    ))
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return findings
