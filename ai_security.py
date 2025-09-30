# ai_security_enhanced.py
import json
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import textwrap

class VulnerabilityType(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    INJECTION = "injection" 
    INTEGER_OVERFLOW = "integer_overflow"
    UNINITIALIZED_MEMORY = "uninitialized_memory"
    FORMAT_STRING = "format_string"
    MEMORY_LEAK = "memory_leak"
    UNSAFE_FUNCTION = "unsafe_function"

@dataclass
class SecurityFinding:
    type: VulnerabilityType
    severity: str
    confidence: float
    location: str
    description: str
    explanation: str
    risk_impact: str
    fix_suggestion: str
    code_example: str
    cwe_id: str

class AdvancedSecurityAnalyzer:
    """
    Advanced AI-powered security analyzer with plain English explanations
    """
    
    def __init__(self, min_confidence: float = 0.5):
        self.knowledge_base = self._build_knowledge_base()
        self.min_confidence = min_confidence
        
    def _build_knowledge_base(self) -> Dict[str, Any]:
        """Build comprehensive security knowledge base"""
        return {
            VulnerabilityType.BUFFER_OVERFLOW: {
                'patterns': [
                    r'ArrayAccess.*index.*IdentifierLiteral',
                    r'InfixExpression.*operator.*[<>].*IntegerLiteral',
                    r'CallExpression.*read.*IdentifierLiteral',
                    r'WhileStatement.*condition.*no.*bound'
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-120',
                'description': 'Buffer Overflow Vulnerability',
                'explanation': 'This occurs when a program writes more data to a buffer than it can hold, potentially overwriting adjacent memory.',
                'risk_impact': 'Can lead to arbitrary code execution, system crashes, or data corruption. Attackers can exploit this to take control of your program.',
                'fix_suggestion': 'Always validate array indices and buffer sizes. Use bounds checking before buffer operations.',
                'code_example': '// Vulnerable:\narr[i] = value;\n\n// Secure:\nif (i >= 0 && i < arr_size) {\n    arr[i] = value;\n} else {\n    // Handle error\n}'
            },
            VulnerabilityType.INJECTION: {
                'patterns': [
                    r'CallExpression.*exec.*InfixExpression.*\+',
                    r'CallExpression.*system.*StringLiteral.*IdentifierLiteral',
                    r'StringLiteral.*SELECT.*WHERE.*InfixExpression',
                    r'CallExpression.*eval.*IdentifierLiteral'
                ],
                'severity': 'CRITICAL',
                'cwe': 'CWE-89',
                'description': 'Code/SQL Injection Vulnerability',
                'explanation': 'This happens when untrusted user input is directly concatenated into commands or queries without proper sanitization.',
                'risk_impact': 'Attackers can execute arbitrary commands, steal sensitive data, or modify database contents.',
                'fix_suggestion': 'Use parameterized queries for SQL and input validation/sanitization for commands. Never trust user input.',
                'code_example': '// Vulnerable:\nquery = "SELECT * FROM users WHERE name=\\" + user_input + "\\"";\n\n// Secure:\nquery = "SELECT * FROM users WHERE name=?";\n// Use parameterized queries with prepared statements'
            },
            VulnerabilityType.INTEGER_OVERFLOW: {
                'patterns': [
                    r'InfixExpression.*operator.*\*.*IntegerLiteral.*\d{4}',
                    r'InfixExpression.*operator.*\+.*IntegerLiteral.*\d{6}',
                    r'CallExpression.*malloc.*InfixExpression'
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-190',
                'description': 'Integer Overflow Vulnerability',
                'explanation': 'Occurs when an arithmetic operation results in a number too large for the allocated memory space, causing wraparound.',
                'risk_impact': 'Can lead to buffer overflows, incorrect calculations, or security bypasses in size checks.',
                'fix_suggestion': 'Use overflow-checking arithmetic operations and validate numerical inputs.',
                'code_example': '// Vulnerable:\nint total = a * b;\n\n// Secure:\nif (a > 0 && b > 0 && a > INT_MAX / b) {\n    // Handle overflow\n} else {\n    int total = a * b;\n}'
            },
            VulnerabilityType.UNINITIALIZED_MEMORY: {
                'patterns': [
                    r'IdentifierLiteral.*LetStatement.*no.*value',
                    r'AssignStatement.*value.*None',
                    r'IdentifierLiteral.*before.*assignment'
                ],
                'severity': 'MEDIUM',
                'cwe': 'CWE-457',
                'description': 'Use of Uninitialized Variable',
                'explanation': 'Using variables before they are assigned values can lead to unpredictable behavior and information disclosure.',
                'risk_impact': 'May expose sensitive memory contents or cause unpredictable program behavior.',
                'fix_suggestion': 'Always initialize variables before use. Set default values during declaration.',
                'code_example': '// Vulnerable:\nint x;\nprintf("%d", x);\n\n// Secure:\nint x = 0;\nprintf("%d", x);'
            },
            VulnerabilityType.FORMAT_STRING: {
                'patterns': [
                    r'CallExpression.*printf.*IdentifierLiteral',
                    r'CallExpression.*sprintf.*no.*format',
                    r'StringLiteral.*%s.*IdentifierLiteral'
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-134',
                'description': 'Format String Vulnerability',
                'explanation': 'Occurs when user input is used directly as a format string, allowing attackers to read or write arbitrary memory.',
                'risk_impact': 'Can lead to information disclosure, memory corruption, or arbitrary code execution.',
                'fix_suggestion': 'Use constant format strings. Never use user input directly in format functions.',
                'code_example': '// Vulnerable:\nprintf(user_input);\n\n// Secure:\nprintf("%s", user_input);'
            },
            # Extended detections
            'RACE_CONDITION': {
                'patterns': [
                    r'CallExpression.*read.*CallExpression.*write',
                    r'LetStatement.*shared.*IdentifierLiteral'
                ],
                'severity': 'MEDIUM',
                'cwe': 'CWE-362',
                'description': 'Potential Race Condition',
                'explanation': 'Multiple operations appear to access shared state without synchronization.',
                'risk_impact': 'May cause inconsistent state, data corruption, or security bypass.',
                'fix_suggestion': 'Use locking or atomic operations around shared state.',
                'code_example': '// Example: add locks around shared variable updates.'
            },
            'WEAK_CRYPTO': {
                'patterns': [
                    r'CallExpression.*md5',
                    r'CallExpression.*sha1',
                    r'StringLiteral.*DES'
                ],
                'severity': 'HIGH',
                'cwe': 'CWE-327',
                'description': 'Use of Weak Cryptography',
                'explanation': 'Use of outdated algorithms like MD5/SHA1/DES is insecure.',
                'risk_impact': 'May allow attackers to crack hashes or decrypt data.',
                'fix_suggestion': 'Use modern algorithms like SHA-256, SHA-3, or AES-GCM.',
                'code_example': '// Replace md5(...) with sha256(...).'
            }
        }
    
    def analyze_with_explanations(self, ast_file: str) -> Dict[str, Any]:
        """Perform security analysis with detailed explanations"""
        print("   Scanning for security vulnerabilities...")
        
        try:
            with open(ast_file, 'r') as f:
                ast_data = json.load(f)
            
            findings = self._deep_ast_analysis(ast_data)
            # Filter by minimum confidence but never drop CRITICAL
            filtered = []
            for f in findings:
                if f.severity == 'CRITICAL' or f.confidence >= self.min_confidence:
                    filtered.append(f)
            findings = filtered
            report = self._generate_comprehensive_report(findings)
            
            return report
            
        except Exception as e:
            print(f"   Security analysis error: {e}")
            return {'findings': [], 'summary': {'total': 0}}
    
    def _deep_ast_analysis(self, ast_data: Dict[str, Any]) -> List[SecurityFinding]:
        """Deep AST analysis for vulnerabilities"""
        findings = []
        
        def analyze_node(node: Dict[str, Any], path: str = ""):
            current_path = f"{path}.{node.get('type', 'Unknown')}" if path else node.get('type', 'Unknown')
            
            # Check each vulnerability type
            for vuln_type, vuln_info in self.knowledge_base.items():
                for pattern in vuln_info['patterns']:
                    score = self._pattern_match_score(node, pattern, current_path)
                    if score > 0 and self._context_allows(node, vuln_type):
                        # Weight by severity to slightly boost higher risk types
                        severity_weight = {'CRITICAL': 1.0, 'HIGH': 0.95, 'MEDIUM': 0.9, 'LOW': 0.85}
                        weighted_conf = max(0.05, min(0.99, score * severity_weight.get(vuln_info['severity'], 0.9)))
                        finding = SecurityFinding(
                            type=vuln_type if isinstance(vuln_type, VulnerabilityType) else VulnerabilityType.FORMAT_STRING if 'FORMAT' in vuln_info.get('description','').upper() else VulnerabilityType.INTEGER_OVERFLOW,
                            severity=vuln_info['severity'],
                            confidence=round(weighted_conf, 2),
                            location=self._get_node_location(node),
                            description=vuln_info['description'],
                            explanation=vuln_info['explanation'],
                            risk_impact=vuln_info['risk_impact'],
                            fix_suggestion=vuln_info['fix_suggestion'],
                            code_example=vuln_info['code_example'],
                            cwe_id=vuln_info['cwe']
                        )
                        findings.append(finding)
            
            # Recursive analysis
            for key, value in node.items():
                if isinstance(value, dict):
                    analyze_node(value, current_path)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            analyze_node(item, current_path)
        
        analyze_node(ast_data)
        return self._deduplicate_findings(findings)
    
    def _pattern_match_score(self, node: Dict[str, Any], pattern: str, path: str) -> float:
        """Pattern match scoring: returns 0..1 based on coverage and context depth"""
        node_str = json.dumps(node).lower()
        path_str = path.lower()
        terms = [t for t in pattern.lower().split('.*') if t]
        if not terms:
            return 0.0
        matches = 0
        for term in terms:
            if term in node_str or term in path_str:
                matches += 1
        coverage = matches / len(terms)
        # Depth factor: deeper paths indicate more specific context
        depth = max(1, path_str.count('.') + 1)
        depth_factor = min(1.0, 0.5 + 0.05 * depth)
        # Confidence is product of coverage and depth factor
        return round(coverage * depth_factor, 2)

    def _context_allows(self, node: Dict[str, Any], vuln_type: Any) -> bool:
        """Context-based false-positive reduction rules."""
        ntype = node.get('type')
        # Ignore overly-generic top nodes unless they have strong evidence
        if ntype in ['Program', 'Unknown']:
            return False
        # Format-string: only flag printf/sprintf when first argument is not a constant string
        if isinstance(vuln_type, VulnerabilityType) and vuln_type == VulnerabilityType.FORMAT_STRING:
            if node.get('type') != 'CallExpression':
                return False
            fn = node.get('function', {})
            fname = fn.get('value') if isinstance(fn, dict) else None
            if fname not in ['printf', 'sprintf']:
                return False
            args = node.get('arguments', [])
            if not args:
                return False
            first = args[0]
            if isinstance(first, dict) and first.get('type') == 'StringLiteral':
                # Constant format → likely safe
                return False
        return True
    
    def _get_node_location(self, node: Dict[str, Any]) -> str:
        """Get human-readable location"""
        components = []
        if 'type' in node:
            components.append(node['type'])
        
        for key in ['name', 'function', 'ident']:
            if key in node:
                if isinstance(node[key], dict) and 'value' in node[key]:
                    components.append(f"{key}:{node[key]['value']}")
        
        return " -> ".join(components) if components else "Unknown"
    
    def _deduplicate_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Remove duplicate findings"""
        seen = set()
        unique = []
        
        for finding in findings:
            key = (finding.location, finding.type.value)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        unique.sort(key=lambda x: severity_order.get(x.severity, 4))
        
        return unique
    
    def _generate_comprehensive_report(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate detailed security report"""
        summary = {
            'total_findings': len(findings),
            'by_severity': {},
            'by_type': {},
            'risk_level': 'LOW'
        }
        
        for finding in findings:
            summary['by_severity'][finding.severity] = summary['by_severity'].get(finding.severity, 0) + 1
            summary['by_type'][finding.type.value] = summary['by_type'].get(finding.type.value, 0) + 1
        
        # Determine overall risk level
        if summary['by_severity'].get('CRITICAL', 0) > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['by_severity'].get('HIGH', 0) > 0:
            summary['risk_level'] = 'HIGH'
        elif summary['by_severity'].get('MEDIUM', 0) > 0:
            summary['risk_level'] = 'MEDIUM'
        
        return {
            'summary': summary,
            'findings': [self._finding_to_dict(f) for f in findings]
        }

    def export_report(self, report: Dict[str, Any], out_dir: str = "debug", basename: str = "security_report", formats: list[str] = None) -> list[str]:
        """Export security report to JSON/Markdown files and return file paths"""
        import os
        os.makedirs(out_dir, exist_ok=True)
        if formats is None:
            formats = ["json", "md"]
        paths: list[str] = []
        if "json" in formats:
            json_path = os.path.join(out_dir, f"{basename}.json")
            with open(json_path, 'w') as jf:
                json.dump(report, jf, indent=2)
            paths.append(json_path)
        if "md" in formats:
            md_path = os.path.join(out_dir, f"{basename}.md")
            with open(md_path, 'w') as mf:
                mf.write(self._report_to_markdown(report))
            paths.append(md_path)
        return paths

    def _report_to_markdown(self, report: Dict[str, Any]) -> str:
        summary = report.get('summary', {})
        findings = report.get('findings', [])
        lines = []
        lines.append("# AI Security Analysis Report")
        lines.append("")
        lines.append(f"- Total Findings: {summary.get('total_findings', len(findings))}")
        lines.append(f"- Risk Level: {summary.get('risk_level', 'LOW')}")
        lines.append("")
        if not findings:
            lines.append("No security vulnerabilities detected.")
            return "\n".join(lines)
        by_sev: dict[str, list[dict]] = {}
        for f in findings:
            by_sev.setdefault(f['severity'], []).append(f)
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in by_sev:
                lines.append(f"## {sev} Findings ({len(by_sev[sev])})")
                for i, f in enumerate(by_sev[sev], 1):
                    lines.append(f"### {i}. {f['description']}")
                    lines.append(f"- Location: {f['location']}")
                    lines.append(f"- Confidence: {f['confidence']}")
                    lines.append(f"- CWE: {f['cwe_id']}")
                    lines.append(f"- Explanation: {f['explanation']}")
                    lines.append(f"- Risk: {f['risk_impact']}")
                    lines.append(f"- Fix: {f['fix_suggestion']}")
                    lines.append("")
        return "\n".join(lines)
    
    def _finding_to_dict(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'type': finding.type.value,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'location': finding.location,
            'description': finding.description,
            'explanation': finding.explanation,
            'risk_impact': finding.risk_impact,
            'fix_suggestion': finding.fix_suggestion,
            'code_example': finding.code_example,
            'cwe_id': finding.cwe_id
        }
    
    def should_proceed(self, report: Dict[str, Any], security_level: str) -> bool:
        """Determine if compilation should proceed based on security level"""
        if security_level == 'permissive':
            return True
        
        findings = report.get('findings', [])
        
        if security_level == 'strict':
            # Block on any critical/high findings
            critical_count = len([f for f in findings if f['severity'] in ['CRITICAL', 'HIGH']])
            if critical_count > 0:
                self._print_detailed_report(report)
                return False
        
        self._print_detailed_report(report)
        return True
    
    def _print_detailed_report(self, report: Dict[str, Any]):
        """Print comprehensive security report"""
        findings = report.get('findings', [])
        summary = report.get('summary', {})
        
        print(f"\n   AI SECURITY ASSESSMENT")
        print("   " + "=" * 50)
        print(f"   Total Findings: {summary.get('total_findings', 0)}")
        print(f"   Risk Level: {summary.get('risk_level', 'LOW')}")
        
        if not findings:
            print("   No security vulnerabilities detected!")
            return
        
        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Print findings with detailed explanations
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                print(f"\n   {severity} SEVERITY:")
                print("   " + "-" * 40)
                
                for i, finding in enumerate(by_severity[severity], 1):
                    print(f"   {i}. {finding['description']}")
                    print(f"      Location: {finding['location']}")
                    print(f"      Explanation: {finding['explanation']}")
                    print(f"      Risk: {finding['risk_impact']}")
                    print(f"      Fix: {finding['fix_suggestion']}")
                    print(f"      CWE: {finding['cwe_id']}")
                    print(f"      Confidence: {finding['confidence']:.2f}")
                    print()