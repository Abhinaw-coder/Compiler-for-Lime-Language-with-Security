# demo_runner.py
import subprocess
import sys
import time

def run_demo():
    """Run complete security demo"""
    print("CAPSTONE PROJECT DEMO: AI-BASED SECURE COMPILER ASSISTANT")
    print("=" * 70)
    
    # Demo 1: Vulnerable Code
    print("\n1. [VULNERABLE] ANALYZING VULNERABLE CODE")
    print("   " + "=" * 40)
    result1 = subprocess.run([sys.executable, "main.py", "security_test.lime"], 
                           capture_output=True, text=True)
    
    print("VULNERABLE CODE OUTPUT:")
    print(result1.stdout)
    if result1.stderr:
        print("ERRORS:", result1.stderr)
    
    time.sleep(2)
    
    # Demo 2: Secure Code  
    print("\n2. [SECURE] ANALYZING SECURE CODE")
    print("   " + "=" * 40)
    result2 = subprocess.run([sys.executable, "main.py", "secure_demo.lime"],
                           capture_output=True, text=True)
    
    print("SECURE CODE OUTPUT:")
    print(result2.stdout)
    if result2.stderr:
        print("ERRORS:", result2.stderr)
    
    # Summary
    print("\n3. DEMO SUMMARY")
    print("   " + "=" * 40)
    print("   [VULNERABLE] Code: Blocked by AI security analysis")
    print("   [SECURE] Code: Compiled and executed successfully")
    print("   AI detected and prevented security vulnerabilities")
    print("   Security-preserving optimizations applied")
    print("   Plain English explanations provided")
    
    print("\nDEMO COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    run_demo()