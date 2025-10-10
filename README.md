# Compiler-for-Lime-Language

supported data types : string , float , int
supported operations : plus , minus , multiplication , division , modulus , comparison , assignment
supported symbols : colon , comma , arrow , semi colon(has to end with semi colon) , () , {} 
supported keywords : let , fn , return , if , else , true , false, while , break , continue , for , import
alternative keywords are supported 
example lit will be same as lit

AST.json will have the syntax tree of the progarm in it
ir.ll has the intermediate code generation

if you want to see the tokens from lexical analyser itll be printed when the flag is true ( look at main.py) 
syntax tree will come in ast.json if flag is true
same for intermediate code and running code

---

## New: AI-Based Secure Compiler Assistant (Frontend + API)

A local web app has been added to compile and analyze Lime code with AI-driven security checks and security-preserving optimizations.

- Frontend: `ui/index.html`, `ui/styles.css`, `ui/app.js`
- API server: `server.py` (Flask)
- Security analyzer: `ai_security.py` (AdvancedSecurityAnalyzer)
- Optimizer: `security_optimizer.py` (SecurityPreservingOptimizer)

### Run locally (Windows PowerShell)

1) Install dependencies (once):

```
python -m pip install --upgrade pip
python -m pip install flask llvmlite
```

2) Start the server:

```
python server.py
```

3) Open the app in your browser:

```
http://127.0.0.1:5000/
```

### Using the app
- Paste or load sample Lime programs from the pills (Buffer Overflow/SQL Injection/Command Injection/Secure Code).
- Adjust the minimum confidence slider if you want to tune findings.
- Click "Compile & Analyze".
- The right pane shows vulnerability count and details with plain-English explanations and CWE references.
- Parser/Compiler errors (if any) appear in the Errors panel. IR is shown below for debugging.

Artifacts are written to the `debug/` folder: `ast.json`, `ir_ui.ll`, and security report exports when run via the CLI flow.
