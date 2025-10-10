from flask import Flask, request, jsonify, send_from_directory
import os
import json
import time
import logging
import platform
import subprocess

from typing import Any, Dict

# Import compiler components
from Lexer import Lexer
from Parser import Parser
from Compiler import Compiler
from ai_security import AdvancedSecurityAnalyzer
import llvmlite.binding as llvm
from ctypes import CFUNCTYPE, c_int

app = Flask(__name__, static_folder="ui", static_url_path="/")

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Ensure debug directory exists for AST/IR artifacts
os.makedirs("debug", exist_ok=True)

@app.get("/")
def index():
    return send_from_directory("ui", "index.html")

@app.get("/api/download")
def download_file():
    """Download latest AST JSON or IR file produced by the UI run"""
    import flask
    ftype = request.args.get("type", "ast")
    if ftype == "ir":
        filename = "ir_ui.ll"
    else:
        filename = "ast.json"
    path = os.path.join("debug", filename)
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": f"Artifact not found: {filename}"}), 404
    as_name = filename
    return flask.send_from_directory("debug", filename, as_attachment=True, download_name=as_name)


def _execute_module_and_capture(module) -> Dict[str, Any]:
    """Compile the module IR to an executable using Clang, run it, and capture stdout and return code."""
    result: Dict[str, Any] = {
        "ran": False,
        "returnCode": None,
        "stdout": "",
        "duration_ms": 0.0,
        "error": None,
    }
    try:
        # Save IR to a file
        ir_path = os.path.join("debug", "ir_ui.ll")
        with open(ir_path, "w", encoding="utf-8") as f:
            f.write(str(module))

        # Define path to clang (adjust based on your installation)
        llvm_bin = r"C:\Program Files\LLVM\bin"  # Default Clang bin directory
        clang_path = os.path.join(llvm_bin, "clang.exe")

        # Check if clang exists
        if not os.path.exists(clang_path):
            result["error"] = "Clang not found. Please install LLVM/Clang and add its bin directory to your PATH (e.g., C:\\Program Files\\LLVM\\bin)."
            logger.error(result["error"])
            return result

        # Compile IR directly to executable using clang
        exe_path = os.path.join("debug", "ir_ui.exe")
        clang_cmd = [clang_path, "-x", "ir", ir_path, "-o", exe_path]
        logger.debug(f"Running clang: {' '.join(clang_cmd)}")
        subprocess.run(clang_cmd, check=True, capture_output=True)

        # Run the executable and capture output
        logger.debug("Capturing output...")
        start = time.time()
        run_result = subprocess.run([exe_path], check=True, capture_output=True, text=True)
        et = time.time()
        result.update({
            "ran": True,
            "returnCode": run_result.returncode,
            "stdout": run_result.stdout.strip(),
            "duration_ms": round((et - start) * 1000, 3)
        })
        logger.debug(f"Execution completed with return code: {result['returnCode']}, stdout: {result['stdout']}")

        # Cleanup
        os.remove(exe_path)

        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Execution failed: {str(e)}, stderr: {e.stderr}")
        result["error"] = f"Execution failed: {str(e)}"
        return result
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}", exc_info=True)
        result["error"] = f"Execution failed: {str(e)}"
        return result

@app.post("/api/analyze")
def analyze():
    try:
        data: Dict[str, Any] = request.get_json(force=True) or {}
        code: str = data.get("code", "")
        min_conf: float = float(data.get("minConfidence", 0.5))
        security_level: str = data.get("securityLevel", "strict")
        do_optimize: bool = bool(data.get("optimize", True))
        do_run: bool = bool(data.get("run", True))

        if not isinstance(code, str) or len(code.strip()) == 0:
            return jsonify({"ok": False, "error": "No code provided"}), 400

        with open(os.path.join("debug", "ui_input.lime"), "w", encoding="utf-8") as f:
            f.write(code)

        l = Lexer(source=code)
        p = Parser(lexer=l)
        program = p.parse_program()
        parse_errors = list(p.errors)

        ast_json = None
        ast_path = os.path.join("debug", "ast.json")
        ir_path = os.path.join("debug", "ir_ui.ll")

        if not parse_errors and program is not None:
            ast_json = program.json()
            with open(ast_path, "w", encoding="utf-8") as f:
                json.dump(ast_json, f, indent=2)

        compile_errors = []
        ir_text = ""
        module = None
        if not parse_errors and program is not None:
            try:
                c = Compiler()
                c.compile(node=program)
                module = c.module
                if do_optimize:
                    try:
                        from security_optimizer import SecurityPreservingOptimizer
                        optimizer = SecurityPreservingOptimizer(module)
                        module = optimizer.optimize()
                    except Exception as opt_err:
                        compile_errors.append(f"Optimizer warning: {opt_err}")
                module.triple = llvm.get_default_triple()
                ir_text = str(module)
                if c.errors:
                    compile_errors.extend(c.errors)
                with open(ir_path, "w", encoding="utf-8") as f:
                    f.write(ir_text)
            except Exception as e:
                compile_errors.append(f"Compilation exception: {e}")

        security_report = {"summary": {"total_findings": 0, "risk_level": "LOW"}, "findings": []}
        blocked = False
        if ast_json is not None:
            try:
                analyzer = AdvancedSecurityAnalyzer(min_confidence=min_conf)
                security_report = analyzer.analyze_with_explanations(ast_path)
                findings = security_report.get("findings", [])
                if security_level == "strict":
                    blocked = any(f.get("severity") in ["CRITICAL", "HIGH"] for f in findings)
            except Exception as e:
                security_report = {"summary": {"total_findings": 0, "risk_level": "LOW"}, "findings": [], "error": str(e)}

        execution = None
        if do_run and not parse_errors and not blocked and module is not None:
            logger.debug("Attempting to execute module...")
            execution = _execute_module_and_capture(module)
        else:
            logger.debug(f"Execution skipped: do_run={do_run}, parse_errors={bool(parse_errors)}, blocked={blocked}, module={module is not None}")

        return jsonify({
            "ok": True,
            "parseErrors": parse_errors,
            "compileErrors": compile_errors,
            "ast": ast_json,
            "ir": ir_text,
            "security": security_report,
            "blocked": blocked,
            "execution": execution,
            "artifacts": {
                "astAvailable": bool(ast_json),
                "irAvailable": bool(ir_text),
                "astUrl": "/api/download?type=ast",
                "irUrl": "/api/download?type=ir"
            }
        })
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)