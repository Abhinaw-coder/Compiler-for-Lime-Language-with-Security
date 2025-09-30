import json
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
import numpy as np
from dataclasses import dataclass
from enum import Enum
import hashlib
import subprocess
import sys

class VulnerabilityType(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    INJECTION = "injection"
    INTEGER_OVERFLOW = "integer_overflow"
    UNINITIALIZED_MEMORY = "uninitialized_memory"
    FORMAT_STRING = "format_string"

@dataclass
class SecurityFinding:
    vulnerability_type: VulnerabilityType
    severity: str
    confidence: float
    location: str
    description: str
    recommendation: str
    code_snippet: str
    detection_method: str

class AISecurityAnalyzer:
    def __init__(self):
        self.vulnerability_db = self._initialize_vatabase()
        
    def _initialize_vatabase(self) -> Dict[str, Any]:
        return {
            VulnerabilityType.BUFFER_OVERFLOW: {
                'patterns': [
                    r'ArrayAccess.*index.*IdentifierLiteral',
                    r'InfixExpression.*operator.*[<>]',
                    r'CallExpression.*read.*IdentifierLiteral'
                ],
                'severity': 'HIGH',
                'description': 'Potential buffer overflow',
                'recommendation': 'Add bounds checking'
            },
            VulnerabilityType.INJECTION: {
                'patterns': [
                    r'CallExpression.*exec.*InfixExpression.*\+',
                    r'CallExpression.*system.*StringLiteral',
                    r'StringLiteral.*SELECT.*WHERE.*InfixExpression'
                ],
                'severity': 'CRITICAL', 
                'description': 'Potential code injection',
                'recommendation': 'Use parameterized queries'
            },
            VulnerabilityType.INTEGER_OVERFLOW: {
                'patterns': [
                    r'InfixExpression.*operator.*\*.*IntegerLiteral',
                    r'InfixExpression.*operator.*\+.*IntegerLiteral'
                ],
                'severity': 'HIGH',
                'description': 'Potential integer overflow',
                'recommendation': 'Use bounds checking'
            }
        }
    
    def load_and_analyze_ast(self, ast_file: str) -> List[SecurityFinding]:
        print("🔍 AI Security Analysis Starting...")
        
        try:
            ast_data = self._load_ast_file(ast_file)
            if not ast_data:
                return []
            
            findings = []
            findings.extend(self._pattern_analysis(ast_data))
            
            return self._filter_findings(findings)
            
        except Exception as e:
            print(f"❌ Analysis error: {e}")
            return []
    
    def _load_ast_file(self, ast_file: str) -> Optional[Dict[str, Any]]:
        try:
            with open(ast_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading AST: {e}")
            return None
    
    def _pattern_analysis(self, ast_data: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        def scan_node(node: Dict[str, Any], path: str = ""):
            current_path = f"{path}.{node.get('type', 'Unknown')}" if path else node.get('type', 'Unknown')
            
            for vuln_type, vuln_info in self.vulnerability_db.items():
                for pattern in vuln_info['patterns']:
                    if self._match_pattern(node, pattern, current_path):
                        finding = SecurityFinding(
                            vulnerability_type=vuln_type,
                            severity=vuln_info['severity'],
                            confidence=0.85,
                            location=self._extract_location(node),
                            description=vuln_info['description'],
                            recommendation=vuln_info['recommendation'],
                            code_snippet=self._extract_code_snippet(node),
                            detection_method="ai_pattern"
                        )
                        findings.append(finding)
            
            for key, value in node.items():
                if isinstance(value, dict):
                    scan_node(value, current_path)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            scan_node(item, current_path)
        
        scan_node(ast_data)
        return findings
    
    def _match_pattern(self, node: Dict[str, Any], pattern: str, path: str) -> bool:
        node_str = json.dumps(node).lower()
        path_str = path.lower()
        pattern_terms = pattern.lower().split('.*')
        
        for term in pattern_terms:
            if term and term not in node_str and term not in path_str:
                return False
        return True
    
    def _extract_location(self, node: Dict[str, Any]) -> str:
        components = []
        if 'type' in node:
            components.append(node['type'])
        for key in ['name', 'function', 'ident']:
            if key in node and isinstance(node[key], dict) and 'value' in node[key]:
                components.append(f"{key}:{node[key]['value']}")
        return " -> ".join(components)
    
    def _extract_code_snippet(self, node: Dict[str, Any]) -> str:
        try:
            if node.get('type') == 'CallExpression':
                func_name = self._extract_function_name(node)
                args = []
                if 'arguments' in node:
                    for arg in node['arguments']:
                        if 'value' in arg:
                            args.append(str(arg['value']))
                return f"{func_name}({', '.join(args)})"
            elif node.get('type') == 'InfixExpression':
                left = self._extract_code_snippet(node.get('left_node', {}))
                right = self._extract_code_snippet(node.get('right_node', {}))
                return f"{left} {node.get('operator', '')} {right}"
            elif 'value' in node:
                return str(node['value'])
        except Exception:
            pass
        return json.dumps(node)[:100]
    
    def _extract_function_name(self, node: Dict[str, Any]) -> str:
        if 'function' in node and 'value' in node['function']:
            return node['function']['value']
        return "unknown"
    
    def _filter_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (finding.location, finding.vulnerability_type.value)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        severity_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        unique_findings.sort(key=lambda x: (severity_rank.get(x.severity, 4), -x.confidence))
        return unique_findings
    
    def print_report(self, findings: List[SecurityFinding]):
        print("\n" + "="*80)
        print("🛡️  AI SECURITY ANALYSIS REPORT")
        print("="*80)
        
        if not findings:
            print("✅ No security vulnerabilities detected!")
            return
        
        by_severity = {}
        for finding in findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                print(f"\n🔴 {severity} SEVERITY ({len(by_severity[severity])}):")
                for i, finding in enumerate(by_severity[severity], 1):
                    print(f"  {i}. {finding.vulnerability_type.value.upper()}")
                    print(f"     📍 {finding.location}")
                    print(f"     📝 {finding.description}")
                    print(f"     💡 {finding.recommendation}")
                    print(f"     🎯 {finding.detection_method} (Confidence: {finding.confidence:.2f})")
        
        print(f"\n📊 Total: {len(findings)} vulnerabilities found")
        print("="*80)

def main():
    if len(sys.argv) < 2:
        print("Usage: python ai_security_analyzer.py <source_file>")
        sys.exit(1)
    
    source_file = sys.argv[1]
    
    print("🔒 Running AI Security Analysis...")
    
    # First run compiler to generate AST
    try:
        print("1. Compiling to generate AST...")
        result = subprocess.run(['python', 'main.py'], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Compilation failed: {result.stderr}")
            return
    except Exception as e:
        print(f"❌ Compilation error: {e}")
        return
    
    # Run security analysis
    analyzer = AISecurityAnalyzer()
    findings = analyzer.load_and_analyze_ast("ast.json")
    analyzer.print_report(findings)
    
    # Exit with error code if critical issues found
    critical_count = len([f for f in findings if f.severity in ['CRITICAL', 'HIGH']])
    sys.exit(1 if critical_count > 0 else 0)

if __name__ == "__main__":
    main()