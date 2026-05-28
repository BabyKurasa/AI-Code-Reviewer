from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CodeRequest(BaseModel):
    code: str
    language: str

class CodeResponse(BaseModel):
    language: str
    complexity: str
    score: int
    suggestions: List[str]
    bugs: List[str]
    execution_output: Optional[str] = None

def detect_python_bugs(code):
    bugs = []
    lines = code.split('\n')
    
    # 1. Check for undefined variables
    assigned_vars = set()
    used_vars = set()
    
    for i, line in enumerate(lines):
        # Skip comments
        if line.strip().startswith('#'):
            continue
        
        # Find variable assignments
        assign_match = re.search(r'^(\w+)\s*=', line.strip())
        if assign_match:
            assigned_vars.add(assign_match.group(1))
        
        # Find function definitions
        func_match = re.search(r'def\s+(\w+)', line)
        if func_match:
            assigned_vars.add(func_match.group(1))
        
        # Find variable usage
        words = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', line)
        for word in words:
            if word not in ['if', 'else', 'elif', 'for', 'while', 'print', 'input', 'int', 'float', 'str', 'range', 'len', 'True', 'False', 'None', 'return', 'def', 'class', 'in', 'is', 'not', 'and', 'or', 'with', 'as', 'try', 'except', 'finally', 'raise', 'import', 'from', 'pass', 'break', 'continue', 'lambda']:
                used_vars.add(word)
    
    undefined = used_vars - assigned_vars
    if undefined:
        bugs.append(f"❌ Undefined variables: {', '.join(undefined)} - declare before using")
    
    # 2. Check for missing colons
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and (stripped.startswith('if ') or stripped.startswith('elif ') or stripped.startswith('else') or stripped.startswith('for ') or stripped.startswith('while ') or stripped.startswith('def ') or stripped.startswith('class ') or stripped.startswith('try') or stripped.startswith('except') or stripped.startswith('with')):
            if not stripped.endswith(':'):
                bugs.append(f"❌ Line {i+1}: Missing colon (:) after '{stripped.split()[0]}' statement")
    
    # 3. Check for indentation errors
    expected_indent = 0
    for i, line in enumerate(lines):
        if line.strip():
            spaces = len(line) - len(line.lstrip())
            if spaces % 4 != 0 and spaces > 0:
                bugs.append(f"❌ Line {i+1}: Inconsistent indentation - use 4 spaces")
                break
    
    # 4. Check for division by zero
    if '/ 0' in code or '/0' in code:
        bugs.append("❌ Division by zero detected - this will crash!")
    
    # Check for unguarded division
    div_lines = []
    for i, line in enumerate(lines):
        if '/' in line and 'input' not in line:
            if 'if' not in line and '!= 0' not in code:
                div_lines.append(i+1)
    if div_lines and 'Division by zero' not in bugs[0] if bugs else True:
        bugs.append(f"⚠️ Lines {div_lines}: Division without zero check - may crash")
    
    # 5. Check for syntax errors
    parentheses = code.count('(') - code.count(')')
    if parentheses != 0:
        bugs.append(f"❌ Unmatched parentheses ({code.count('(')} opening, {code.count(')')} closing)")
    
    brackets = code.count('[') - code.count(']')
    if brackets != 0:
        bugs.append(f"❌ Unmatched brackets ({code.count('[')} opening, {code.count(']')} closing)")
    
    braces = code.count('{') - code.count('}')
    if braces != 0:
        bugs.append(f"❌ Unmatched braces ({code.count('{')} opening, {code.count('}')} closing)")
    
    # 6. Check for overwriting built-ins
    builtins = ['sum', 'max', 'min', 'len', 'list', 'dict', 'str', 'int', 'float', 'input', 'print', 'range', 'open']
    for line in lines:
        for builtin in builtins:
            if re.search(rf'\b{builtin}\s*=', line):
                bugs.append(f"⚠️ Overwriting built-in function '{builtin}' - rename variable")
                break
    
    # 7. Check for bare except
    if 'except:' in code and 'except Exception' not in code:
        bugs.append("⚠️ Bare except clause - specify exception type (except Exception as e:)")
    
    return bugs

def detect_javascript_bugs(code):
    bugs = []
    lines = code.split('\n')
    
    # 1. Check for undefined variables
    declared_vars = set()
    used_vars = set()
    
    for line in lines:
        # Variable declarations
        let_match = re.search(r'let\s+(\w+)', line)
        var_match = re.search(r'var\s+(\w+)', line)
        const_match = re.search(r'const\s+(\w+)', line)
        func_match = re.search(r'function\s+(\w+)', line)
        
        if let_match:
            declared_vars.add(let_match.group(1))
        if var_match:
            declared_vars.add(var_match.group(1))
        if const_match:
            declared_vars.add(const_match.group(1))
        if func_match:
            declared_vars.add(func_match.group(1))
        
        # Variable usage
        words = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', line)
        for word in words:
            if word not in ['if', 'else', 'for', 'while', 'return', 'console', 'log', 'true', 'false', 'null', 'undefined', 'function', 'let', 'var', 'const', 'new', 'this', 'typeof', 'instanceof', 'delete', 'void', 'in', 'of']:
                used_vars.add(word)
    
    undefined = used_vars - declared_vars
    if undefined:
        bugs.append(f"❌ Undefined variables: {', '.join(undefined)} - declare with let/const/var")
    
    # 2. Check for missing semicolons
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}') and not stripped.endswith('}') and not stripped.startswith('//') and not stripped.startswith('/*'):
            if 'console' in stripped or 'let ' in stripped or 'var ' in stripped or 'const ' in stripped or 'return' in stripped or '=' in stripped:
                bugs.append(f"⚠️ Line {i+1}: Missing semicolon at end of statement")
    
    # 3. Check for == instead of ===
    for i, line in enumerate(lines):
        if '==' in line and '===' not in line:
            bugs.append(f"⚠️ Line {i+1}: Use === for strict equality instead of ==")
    
    # 4. Check for var usage
    if 'var ' in code:
        bugs.append("⚠️ Using 'var' - use 'let' or 'const' instead for better scoping")
    
    # 5. Check for unmatched parentheses/brackets/braces
    parentheses = code.count('(') - code.count(')')
    if parentheses != 0:
        bugs.append(f"❌ Unmatched parentheses ({code.count('(')} opening, {code.count(')')} closing)")
    
    brackets = code.count('[') - code.count(']')
    if brackets != 0:
        bugs.append(f"❌ Unmatched brackets ({code.count('[')} opening, {code.count(']')} closing)")
    
    braces = code.count('{') - code.count('}')
    if braces != 0:
        bugs.append(f"❌ Unmatched braces ({code.count('{')} opening, {code.count('}')} closing)")
    
    return bugs

def detect_csharp_bugs(code):
    bugs = []
    lines = code.split('\n')
    
    # 1. Check for undefined variables
    declared_vars = set()
    used_vars = set()
    
    for line in lines:
        # Variable declarations
        declare_match = re.search(r'(int|string|double|bool|float|var)\s+(\w+)', line)
        if declare_match:
            declared_vars.add(declare_match.group(2))
        
        # Usage
        words = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', line)
        for word in words:
            if word not in ['Console', 'WriteLine', 'ReadLine', 'if', 'else', 'for', 'while', 'return', 'true', 'false', 'null', 'new', 'class', 'static', 'void', 'public', 'private', 'protected', 'internal', 'int', 'string', 'double', 'bool', 'float', 'var', 'using', 'System', 'namespace', 'Main', 'String', 'Console', 'Write', 'Read', 'WriteLine', 'ReadLine', 'Convert', 'ToString', 'Parse', 'TryParse']:
                used_vars.add(word)
    
    undefined = used_vars - declared_vars
    if undefined:
        bugs.append(f"❌ Undefined variables: {', '.join(undefined)} - declare before using")
    
    # 2. Check for missing semicolons
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}') and not stripped.startswith('//') and not stripped.startswith('/*') and not stripped.startswith('using') and 'class' not in stripped and 'static void Main' not in stripped:
            if 'Console' in stripped or 'int' in stripped or 'string' in stripped or '=' in stripped:
                bugs.append(f"⚠️ Line {i+1}: Missing semicolon at end of statement")
    
    # 3. Check for missing using statement
    if 'Console.WriteLine' in code and 'using System;' not in code:
        bugs.append("❌ Missing 'using System;' - Console class won't be recognized")
    
    # 4. Check for Main method signature
    if 'static void Main' in code and 'string[] args' not in code:
        bugs.append("⚠️ Main method should be: static void Main(string[] args)")
    
    # 5. Check for unmatched braces
    braces = code.count('{') - code.count('}')
    if braces != 0:
        bugs.append(f"❌ Unmatched braces ({code.count('{')} opening, {code.count('}')} closing)")
    
    # 6. Check for missing namespace
    if 'using System;' in code and 'namespace' not in code and 'class Program' in code:
        bugs.append("⚠️ Consider wrapping code in a namespace")
    
    return bugs

def detect_java_bugs(code):
    bugs = []
    
    # 1. Missing main method
    if 'public static void main' in code and 'String[] args' not in code:
        bugs.append("❌ Main method should be: public static void main(String[] args)")
    
    # 2. Missing semicolon
    if 'System.out.println' in code and ';' not in code[code.find('System.out.println'):code.find('System.out.println')+30]:
        bugs.append("❌ Missing semicolon after System.out.println")
    
    # 3. Undeclared variables
    if 'age' in code and 'int age' not in code and 'Integer age' not in code:
        bugs.append("❌ Variable 'age' used but not declared")
    
    # 4. Unmatched braces
    braces = code.count('{') - code.count('}')
    if braces != 0:
        bugs.append(f"❌ Unmatched braces ({code.count('{')} opening, {code.count('}')} closing)")
    
    # 5. Missing class
    if 'public class' not in code and 'class' not in code:
        bugs.append("⚠️ Code should be inside a class definition")
    
    return bugs

def detect_c_bugs(code):
    bugs = []
    
    # 1. Missing return type
    if 'main(' in code and 'int main' not in code and 'void main' not in code:
        bugs.append("⚠️ main() should have return type 'int' or 'void'")
    
    # 2. Missing return statement
    if 'int main' in code and 'return 0' not in code:
        bugs.append("⚠️ Missing 'return 0;' at end of main function")
    
    # 3. Dangerous gets()
    if 'gets(' in code:
        bugs.append("❌ NEVER use gets() - use fgets() instead (security vulnerability)")
    
    # 4. Missing & in scanf
    if 'scanf(' in code and '&' not in code[code.find('scanf('):code.find('scanf(')+20]:
        bugs.append("❌ Missing & operator in scanf - won't store value correctly")
    
    # 5. Unmatched braces
    braces = code.count('{') - code.count('}')
    if braces != 0:
        bugs.append(f"❌ Unmatched braces ({code.count('{')} opening, {code.count('}')} closing)")
    
    # 6. Missing semicolon
    lines = code.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}') and not stripped.startswith('#') and not stripped.startswith('//') and not stripped.startswith('/*'):
            if 'printf' in stripped or 'scanf' in stripped or '=' in stripped:
                bugs.append(f"⚠️ Line {i+1}: Missing semicolon")
                break
    
    return bugs

def detect_cpp_bugs(code):
    bugs = []
    
    # 1. Memory leak
    if 'new ' in code and 'delete' not in code:
        bugs.append("⚠️ Potential memory leak - allocated memory not freed with delete")
    
    # 2. Using namespace std (warning)
    if 'using namespace std' in code:
        bugs.append("⚠️ Avoid 'using namespace std' - use std:: prefix instead")
    
    # 3. Missing return
    if 'int main' in code and 'return 0' not in code:
        bugs.append("⚠️ Missing 'return 0;' in main function")
    
    # 4. Unmatched braces
    braces = code.count('{') - code.count('}')
    if braces != 0:
        bugs.append(f"❌ Unmatched braces ({code.count('{')} opening, {code.count('}')} closing)")
    
    return bugs

def detect_go_bugs(code):
    bugs = []
    
    # 1. Unchecked error
    if 'err :=' in code and 'if err' not in code:
        bugs.append("⚠️ Error returned but not checked - handle errors with 'if err != nil'")
    
    # 2. Missing package
    if 'func main' in code and 'package main' not in code:
        bugs.append("❌ Missing 'package main' declaration")
    
    # 3. Unused variables
    if '_' not in code and ':= ' in code:
        bugs.append("⚠️ Unused variables - prefix with _ to ignore")
    
    return bugs

def detect_rust_bugs(code):
    bugs = []
    
    # 1. Unwrap usage
    if 'unwrap()' in code:
        bugs.append("⚠️ Avoid unwrap() - use match or ? operator for error handling")
    
    # 2. Missing semicolon
    lines = code.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}'):
            if 'println!' in stripped or 'let' in stripped:
                bugs.append(f"⚠️ Line {i+1}: Missing semicolon")
                break
    
    return bugs

def detect_ruby_bugs(code):
    bugs = []
    
    # 1. Missing end
    if code.count('def ') != code.count('end'):
        bugs.append("❌ Missing 'end' keyword - function not closed properly")
    
    # 2. Missing do for blocks
    if '{' in code and 'do' not in code:
        bugs.append("⚠️ Use 'do' for multi-line blocks")
    
    return bugs

def get_complexity_and_score(code, bugs):
    lines = len([l for l in code.split('\n') if l.strip()])
    
    if lines < 10:
        complexity = "Simple"
        base_score = 90
    elif lines < 25:
        complexity = "Moderate"
        base_score = 75
    else:
        complexity = "Complex"
        base_score = 60
    
    # Calculate score based on bugs
    error_count = len([b for b in bugs if '❌' in b])
    warning_count = len([b for b in bugs if '⚠️' in b])
    
    final_score = base_score - (error_count * 15) - (warning_count * 5)
    final_score = max(0, min(100, final_score))
    
    return complexity, final_score

@app.post("/review")
async def review_code(request: CodeRequest):
    code = request.code
    lang = request.language
    
    bugs = []
    suggestions = []
    
    # Detect bugs based on language
    if lang == "python":
        bugs = detect_python_bugs(code)
        suggestions = [
            "💡 Use f-strings for string formatting: f'Hello {name}'",
            "💡 Add docstrings to document functions",
            "💡 Use logging module instead of print() for production",
            "💡 Use list comprehensions for simple loops",
            "💡 Follow PEP 8 style guide"
        ]
    elif lang == "javascript":
        bugs = detect_javascript_bugs(code)
        suggestions = [
            "💡 Use const for variables that don't change",
            "💡 Use let for variables that change",
            "💡 Add error handling with try-catch",
            "💡 Use async/await for promises",
            "💡 Use template literals: `${variable}`"
        ]
    elif lang == "csharp":
        bugs = detect_csharp_bugs(code)
        suggestions = [
            "💡 Use properties instead of public fields",
            "💡 Follow .NET naming conventions (PascalCase)",
            "💡 Use using statements for IDisposable resources",
            "💡 Use string interpolation: $\"Hello {name}\"",
            "💡 Add XML comments for documentation"
        ]
    elif lang == "java":
        bugs = detect_java_bugs(code)
        suggestions = [
            "💡 Follow Java naming conventions (camelCase)",
            "💡 Add Javadoc comments",
            "💡 Use try-catch for exception handling",
            "💡 Use StringBuilder for string concatenation",
            "💡 Use List instead of arrays when possible"
        ]
    elif lang == "c":
        bugs = detect_c_bugs(code)
        suggestions = [
            "💡 Always check return values",
            "💡 Use fgets() instead of gets()",
            "💡 Initialize variables before use",
            "💡 Use const for read-only parameters",
            "💡 Use size_t for array indices"
        ]
    elif lang == "cpp":
        bugs = detect_cpp_bugs(code)
        suggestions = [
            "💡 Use smart pointers instead of raw pointers",
            "💡 Prefer std::string over char arrays",
            "💡 Use range-based for loops",
            "💡 Use constexpr for compile-time constants",
            "💡 Use auto for complex types"
        ]
    elif lang == "go":
        bugs = detect_go_bugs(code)
        suggestions = [
            "💡 Always handle errors explicitly",
            "💡 Use gofmt for consistent formatting",
            "💡 Write benchmarks for performance",
            "💡 Use interfaces for abstraction",
            "💡 Use goroutines for concurrency"
        ]
    elif lang == "rust":
        bugs = detect_rust_bugs(code)
        suggestions = [
            "💡 Use cargo clippy for linting",
            "💡 Implement Debug trait for types",
            "💡 Use Result type for error handling",
            "💡 Use Option type for nullable values",
            "💡 Use iterators instead of loops"
        ]
    elif lang == "ruby":
        bugs = detect_ruby_bugs(code)
        suggestions = [
            "💡 Follow Ruby style guide",
            "💡 Use unless for negative conditions",
            "💡 Prefer symbols over strings as hash keys",
            "💡 Use each instead of for loops",
            "💡 Use puts for debugging"
        ]
    else:
        bugs = ["Select a supported language for detailed analysis"]
        suggestions = ["Supported: Python, JavaScript, C#, Java, C, C++, Go, Rust, Ruby"]
    
    # Add general suggestions
    if len(code) < 100 and code.strip():
        suggestions.append("💡 Add more functionality to your code")
    
    if "TODO" in code:
        suggestions.append("📝 Complete TODO items before deployment")
    
    if "FIXME" in code:
        suggestions.append("🔧 Fix FIXME items")
    
    # Get complexity and score
    complexity, score = get_complexity_and_score(code, bugs)
    
    # Limit to 4 suggestions and 6 bugs
    suggestions = suggestions[:5]
    bugs = bugs[:6] if bugs else ["✅ No critical bugs detected. Code looks good!"]
    
    return CodeResponse(
        language=lang,
        complexity=complexity,
        score=score,
        suggestions=suggestions,
        bugs=bugs,
        execution_output=None
    )

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/")
async def root():
    return {"message": "AI Code Reviewer API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)