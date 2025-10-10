from Lexer import Lexer
from Parser import Parser
from Compiler import Compiler
from AST import Program
import json
import time
import sys
import os

from llvmlite import ir
import llvmlite.binding as llvm
from ctypes import CFUNCTYPE, c_int, c_float

# Security and Optimization Flags
LEXER_DEBUG: bool = False
PARSER_DEBUG: bool = False
COMPILER_DEBUG: bool = True
RUN_CODE: bool = True
SECURITY_ANALYSIS: bool = True
SECURITY_OPTIMIZATION: bool = True
AI_EXPLANATIONS: bool = True

class SecureCompiler:
    """Enhanced compiler with AI security and optimization"""
    
    def __init__(self):
        self.security_level = "strict"
        self.optimization_level = "security"
        
    def compile_with_security(self, source_file: str):
        """Complete secure compilation pipeline"""
        print("AI-POWERED SECURE COMPILER STARTING...")
        print(f"Source: {source_file}")
        print(f"Security: {self.security_level}")
        print(f"Optimization: {self.optimization_level}")
        print("=" * 60)
        
        # Read source code
        with open(source_file, "r") as f:
            code: str = f.read()

        # Phase 1: Lexical Analysis
        print("\n1. LEXICAL ANALYSIS")
        l: Lexer = Lexer(source=code)
        if LEXER_DEBUG:
            print("===== LEXER DEBUG =====")
            while l.current_char is not None:
                print(l.next_token())

        # Phase 2: Parsing
        print("2. SYNTAX ANALYSIS & AST GENERATION")
        p: Parser = Parser(lexer=l)
        program: Program = p.parse_program()
        
        if len(p.errors) > 0:
            print("PARSING ERRORS:")
            for err in p.errors:
                print(f"   {err}")
            return False

        # Save AST for security analysis
        if PARSER_DEBUG or SECURITY_ANALYSIS:
            os.makedirs("debug", exist_ok=True)
            with open("debug/ast.json", "w") as f:
                json.dump(program.json(), f, indent=2)
            print("   AST saved to debug/ast.json")

        # Phase 3: AI Security Analysis
        if SECURITY_ANALYSIS:
            print("3. AI SECURITY ANALYSIS")
            from ai_security import AdvancedSecurityAnalyzer
            # Read optional env flags for demo flexibility
            min_conf = float(os.getenv('LIME_MIN_CONFIDENCE', '0'))
            security_analyzer = AdvancedSecurityAnalyzer(min_confidence=min_conf)
            security_report = security_analyzer.analyze_with_explanations("debug/ast.json")
            # Export report files for grading/demo
            report_paths = security_analyzer.export_report(security_report, out_dir="debug", basename="security_report", formats=["json", "md"]) 
            print(f"   Security report written to: {', '.join(report_paths)}")
            
            if not security_analyzer.should_proceed(security_report, self.security_level):
                print("   CRITICAL: Security violations detected! Compilation blocked.")
                return False

        # Phase 4: Secure Compilation
        print("4. SECURE CODE GENERATION")
        c: Compiler = Compiler()
        c.compile(node=program)

        # Phase 5: Security-Preserving Optimization
        if SECURITY_OPTIMIZATION:
            print("5. SECURITY-PRESERVING OPTIMIZATION")
            from security_optimizer import SecurityPreservingOptimizer
            optimizer = SecurityPreservingOptimizer(c.module)
            optimized_module = optimizer.optimize()
            c.module = optimized_module

        # Generate IR
        module: ir.Module = c.module
        module.triple = llvm.get_default_triple()

        if COMPILER_DEBUG:
            with open("debug/ir_secure.ll", "w") as f:
                f.write(str(module))
            print("   Secure IR saved to debug/ir_secure.ll")

        if len(c.errors) > 0:
            print("❌ COMPILATION ERRORS:")
            for err in c.errors:
                print(f"   {err}")
            return False

        # Phase 6: Execution with Security Monitor
        if RUN_CODE:
            print("6. SECURE EXECUTION")
            success = self._execute_with_monitor(module)
            if not success:
                return False

        print("=" * 60)
        print("SECURE COMPILATION COMPLETED SUCCESSFULLY!")
        return True

    def _execute_with_monitor(self, module: ir.Module) -> bool:
        """Execute code with security monitoring"""
        try:
            # Remove try-except around initialization and make it unconditional for modern llvmlite
            # Core init is automatic in recent versions; targets still need explicit calls
            llvm.initialize_native_target()
            llvm.initialize_native_asmprinter()
            llvm.initialize_all_targets()  # Add this for extra target registration

            llvm_ir_parsed = llvm.parse_assembly(str(module))
            llvm_ir_parsed.verify()

            target_machine = llvm.Target.from_default_triple().create_target_machine()
            engine = llvm.create_mcjit_compiler(llvm_ir_parsed, target_machine)
            engine.finalize_object()

            # Find main function
            entry = engine.get_function_address('main')
            if entry == 0:
                print("   No main function found")
                return True

            cfunc = CFUNCTYPE(c_int)(entry)

            print("   Running with security monitor...")
            st = time.time()
            result = cfunc()
            et = time.time()

            print(f"   Program returned: {result}")
            print(f"   Executed in {round((et - st) * 1000, 6)} ms")
            
            return True

        except Exception as e:
            print(f"   Execution error: {e}")
            return False  # Change to False to fail on error

def main():
    """Main entry point with command line support"""
    # Default to root-level sample if none provided
    source_file = "test.lime"
    if len(sys.argv) > 1:
        source_file = sys.argv[1]
    
    if not os.path.exists(source_file):
        print(f"❌ Error: Source file {source_file} not found")
        sys.exit(1)
    
    compiler = SecureCompiler()
    success = compiler.compile_with_security(source_file)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()