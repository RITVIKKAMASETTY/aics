import os
import re
import sys
import argparse
import json
from typing import Dict, List, Optional, Tuple, Union, Set
import ast
import subprocess
import tempfile
from pathlib import Path
from openai import OpenAI
from dotenv import load_dotenv
import glob

# Load environment variables
load_dotenv()

class SecurityVulnerability:
    """Class to represent a security vulnerability found in code."""
    def __init__(self, vulnerability_type: str, line_number: int, description: str, code_snippet: str, 
                 file_path: str = None, recommended_fix: str = None, severity: str = "medium"):
        self.vulnerability_type = vulnerability_type
        self.line_number = line_number
        self.description = description
        self.code_snippet = code_snippet
        self.file_path = file_path
        self.recommended_fix = recommended_fix
        self.severity = severity  # "low", "medium", "high", "critical"

    def __str__(self) -> str:
        file_info = f"{self.file_path}:" if self.file_path else ""
        return f"[{self.vulnerability_type}] {file_info}Line {self.line_number}: {self.description}"
    
    def to_dict(self) -> Dict:
        return {
            "type": self.vulnerability_type,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "recommended_fix": self.recommended_fix,
            "severity": self.severity
        }

class ProjectAnalyzer:
    """Analyzes a project directory structure for security vulnerabilities."""
    
    def __init__(self, project_path: str, include_patterns: List[str] = None, exclude_patterns: List[str] = None):
        self.project_path = os.path.abspath(project_path)
        self.include_patterns = include_patterns or ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.php", "*.java"]
        self.exclude_patterns = exclude_patterns or ["*node_modules/*", "*venv/*", "*dist/*", "*build/*", "*.git/*"]
        self.framework_detection_map = self._detect_frameworks()
        
    def _detect_frameworks(self) -> Dict[str, str]:
        """Detect frameworks used in the project."""
        frameworks = {}
        
        # Check for package.json to identify JS frameworks
        package_json_path = os.path.join(self.project_path, "package.json")
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    dependencies = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    
                    if "react" in dependencies:
                        frameworks["react"] = dependencies["react"]
                    if "angular" in dependencies:
                        frameworks["angular"] = dependencies["angular"]
                    if "vue" in dependencies:
                        frameworks["vue"] = dependencies["vue"]
                    if "next" in dependencies:
                        frameworks["next.js"] = dependencies["next"]
            except Exception as e:
                print(f"Error reading package.json: {e}")
        
        # Check for Python frameworks
        requirements_path = os.path.join(self.project_path, "requirements.txt")
        if os.path.exists(requirements_path):
            try:
                with open(requirements_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if "django" in content.lower():
                        frameworks["django"] = "detected"
                    if "flask" in content.lower():
                        frameworks["flask"] = "detected"
                    if "fastapi" in content.lower():
                        frameworks["fastapi"] = "detected"
            except Exception as e:
                print(f"Error reading requirements.txt: {e}")
        
        return frameworks
    
    def find_files_to_analyze(self) -> List[str]:
        """Find all files to analyze based on include/exclude patterns."""
        all_files = []
        
        for root, dirs, files in os.walk(self.project_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(
                glob.fnmatch.fnmatch(os.path.join(root, d), pattern) 
                for pattern in self.exclude_patterns
            )]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if file matches include patterns and not exclude patterns
                if any(glob.fnmatch.fnmatch(file, pattern) for pattern in self.include_patterns) and \
                   not any(glob.fnmatch.fnmatch(file_path, pattern) for pattern in self.exclude_patterns):
                    all_files.append(file_path)
        
        return all_files
    
    def analyze(self) -> Dict[str, List[SecurityVulnerability]]:
        """Analyze the entire project directory."""
        files_to_analyze = self.find_files_to_analyze()
        results = {}
        
        for file_path in files_to_analyze:
            analyzer = CodeAnalyzer(file_path, self.framework_detection_map)
            vulnerabilities = analyzer.analyze()
            
            if vulnerabilities:
                results[file_path] = vulnerabilities
        
        return results
    
    def generate_project_context(self) -> str:
        """Generate a context description of the project for AI-assisted analysis."""
        frameworks = ", ".join([f"{k} ({v})" for k, v in self.framework_detection_map.items()]) if self.framework_detection_map else "No frameworks detected"
        
        file_count = len(self.find_files_to_analyze())
        file_types = set()
        
        # Sample a few directories to understand structure
        dirs = []
        for root, directories, files in os.walk(self.project_path):
            rel_path = os.path.relpath(root, self.project_path)
            if rel_path != "." and not any(excluded in rel_path for excluded in ["node_modules", "venv", ".git"]):
                dirs.append(rel_path)
                # Get file extensions
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext:
                        file_types.add(ext)
            if len(dirs) >= 10:  # Limit to 10 directories for context
                break
                
        context = f"""
        Project Overview:
        - Directory: {self.project_path}
        - Frameworks: {frameworks}
        - File count: {file_count}
        - File types: {', '.join(sorted(file_types))}
        - Key directories: {', '.join(dirs[:10])}
        """
        
        return context

class CodeAnalyzer:
    """Analyzes code for security vulnerabilities and other issues."""
    
    # Dictionary of common security vulnerability patterns
    SECURITY_PATTERNS = {
        "command_injection": r"(?:os\.system|subprocess\.call|subprocess\.Popen|subprocess\.run|eval|exec)\s*\(",
        "sql_injection": r"(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f|\".*\{|'.*\{|\".*\+|'.*\+)",
        "path_traversal": r"(?:open|file|os\.path\.join)\s*\(\s*(?:f|\".*\{|'.*\{|\".*\+|'.*\+)",
        "insecure_deserialization": r"(?:pickle\.loads|yaml\.load|json\.loads)\s*\(",
        "hardcoded_credentials": r"(?:password|passwd|pwd|secret|key|token|api_key)\s*=\s*[\'\"][^\'\"\s]+[\'\"]",
        "insecure_random": r"(?:random\.|randint|choice)",
        "debug_enabled": r"(?:DEBUG\s*=\s*True|debug\s*=\s*True)",
        "insecure_crypto": r"(?:md5|sha1)",
        "insecure_file_permissions": r"(?:os\.chmod\([^\)]*0o777)",
        "eval_usage": r"(?:eval\()",
        "xxe_vulnerability": r"(?:etree\.parse|minidom\.parse|sax\.parse)",
        "cors_wildcard": r"(?:Access-Control-Allow-Origin:\s*\*)",
        "unsafe_yaml": r"(?:yaml\.load\([^,\)]+\))",
        "unsafe_regex": r"(?:re\.match\(.*\+)",
        "dangerous_redirect": r"(?:redirect\(\s*(?:request\.args|request\.POST|params))",
    }
    
    # JavaScript/React specific patterns
    JS_PATTERNS = {
        "react_dangerous_html": r"dangerouslySetInnerHTML",
        "react_no_prop_types": r"PropTypes",
        "insecure_innerhtml": r"\.innerHTML\s*=",
        "eval_usage": r"(?:eval\(|new Function\()",
        "document_write": r"document\.write\(",
        "href_javascript": r"href\s*=\s*['\"]javascript:",
        "insecure_localstorage": r"localStorage\.setItem\([^,]+,\s*(?!JSON\.stringify)",
        "insecure_authentication": r"(?:auth|login|password|credentials).*localStorage",
        "insecure_random_js": r"Math\.random\(\)",
        "postmessage_wildcard": r"postMessage\([^,]+,\s*['\*]",
        "dom_xss": r"(?:innerHTML|outerHTML)\s*=\s*(?!.*DOMPurify)",
    }

    def __init__(self, file_path: str, frameworks: Dict[str, str] = None):
        self.file_path = file_path
        self.code_content = self._read_file()
        self.lines = self.code_content.split('\n')
        self.language = self._detect_language()
        self.frameworks = frameworks or {}
        
    def _read_file(self) -> str:
        """Read the file content."""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return ""
    
    def _detect_language(self) -> str:
        """Detect the programming language based on file extension."""
        ext = os.path.splitext(self.file_path)[1].lower()
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'react',
            '.tsx': 'react_typescript',
            '.ts': 'typescript',
            '.php': 'php',
            '.java': 'java',
            '.rb': 'ruby',
            '.go': 'go',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
        }
        return language_map.get(ext, 'unknown')
    
    def analyze(self) -> List[SecurityVulnerability]:
        """Analyze the code for security vulnerabilities."""
        vulnerabilities = []
        
        if not self.code_content:
            return vulnerabilities
        
        # Check for language-specific analyzers
        if self.language == 'python':
            vulnerabilities.extend(self._analyze_python())
        elif self.language in ['javascript', 'react', 'react_typescript', 'typescript']:
            vulnerabilities.extend(self._analyze_javascript())
        
        # Generic pattern-based checks
        vulnerabilities.extend(self._check_patterns())
        
        # Add file path to each vulnerability
        for v in vulnerabilities:
            v.file_path = self.file_path
        
        return vulnerabilities
    
    def _analyze_python(self) -> List[SecurityVulnerability]:
        """Python-specific code analysis using AST."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(self.code_content)
            
            # Check for dangerous eval/exec calls
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if hasattr(node.func, 'id') and node.func.id in ['eval', 'exec']:
                        line_number = node.lineno
                        code_snippet = self.lines[line_number-1].strip()
                        vulnerabilities.append(
                            SecurityVulnerability(
                                "dangerous_eval_exec",
                                line_number,
                                "Dangerous use of eval() or exec() can lead to code injection vulnerabilities.",
                                code_snippet,
                                self.file_path,
                                "Replace with safer alternatives or validate inputs strictly.",
                                "high"
                            )
                        )
                
                # Check for hardcoded secrets in assignments
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and any(secret in target.id.lower() for secret in ['password', 'secret', 'key', 'token']):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                line_number = node.lineno
                                code_snippet = self.lines[line_number-1].strip()
                                vulnerabilities.append(
                                    SecurityVulnerability(
                                        "hardcoded_secret",
                                        line_number,
                                        f"Hardcoded secret detected in variable '{target.id}'.",
                                        code_snippet,
                                        self.file_path,
                                        "Use environment variables or secure secret management.",
                                        "high"
                                    )
                                )
                
            # Check for Django-specific issues
            if 'django' in self.frameworks:
                vulnerabilities.extend(self._check_django_security())
                
            # Check for Flask-specific issues
            if 'flask' in self.frameworks:
                vulnerabilities.extend(self._check_flask_security())
            
        except SyntaxError as e:
            # If there's a syntax error, add it as a vulnerability
            line_number = e.lineno or 1
            code_snippet = self.lines[line_number-1].strip() if line_number <= len(self.lines) else ""
            vulnerabilities.append(
                SecurityVulnerability(
                    "syntax_error",
                    line_number,
                    f"Syntax error: {str(e)}",
                    code_snippet,
                    self.file_path,
                    "Fix the syntax error for proper code execution.",
                    "high"
                )
            )
        except Exception as e:
            # Handle other parsing errors
            vulnerabilities.append(
                SecurityVulnerability(
                    "parsing_error",
                    1,
                    f"Error parsing Python code: {str(e)}",
                    self.code_content[:100] + "..." if len(self.code_content) > 100 else self.code_content,
                    self.file_path,
                    "Check for complex syntax issues.",
                    "medium"
                )
            )
        
        return vulnerabilities
    
    def _check_django_security(self) -> List[SecurityVulnerability]:
        """Check for Django-specific security issues."""
        vulnerabilities = []
        
        # Check for DEBUG=True
        if re.search(r'DEBUG\s*=\s*True', self.code_content):
            line_number = next((i+1 for i, line in enumerate(self.lines) 
                               if re.search(r'DEBUG\s*=\s*True', line)), 1)
            vulnerabilities.append(
                SecurityVulnerability(
                    "django_debug_enabled",
                    line_number,
                    "Django DEBUG mode enabled. This should be disabled in production.",
                    self.lines[line_number-1].strip(),
                    self.file_path,
                    "Set DEBUG = False in production environments.",
                    "high"
                )
            )
        
        # Check for insecure ALLOWED_HOSTS
        if re.search(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"][*]['\"]", self.code_content):
            line_number = next((i+1 for i, line in enumerate(self.lines) 
                               if re.search(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"][*]['\"]", line)), 1)
            vulnerabilities.append(
                SecurityVulnerability(
                    "django_insecure_allowed_hosts",
                    line_number,
                    "Django ALLOWED_HOSTS set to wildcard '*'. This is insecure in production.",
                    self.lines[line_number-1].strip(),
                    self.file_path,
                    "Specify explicit allowed hosts in production.",
                    "medium"
                )
            )
        
        return vulnerabilities
    
    def _check_flask_security(self) -> List[SecurityVulnerability]:
        """Check for Flask-specific security issues."""
        vulnerabilities = []
        
        # Check for debug=True in app.run()
        if re.search(r'\.run\(.*debug\s*=\s*True', self.code_content):
            line_number = next((i+1 for i, line in enumerate(self.lines) 
                               if re.search(r'\.run\(.*debug\s*=\s*True', line)), 1)
            vulnerabilities.append(
                SecurityVulnerability(
                    "flask_debug_enabled",
                    line_number,
                    "Flask debug mode enabled. This should be disabled in production.",
                    self.lines[line_number-1].strip(),
                    self.file_path,
                    "Set debug=False in production environments.",
                    "high"
                )
            )
        
        return vulnerabilities
    
    def _analyze_javascript(self) -> List[SecurityVulnerability]:
        """JavaScript and React-specific code analysis."""
        vulnerabilities = []
        
        # Pattern-based analysis for JavaScript/React
        for vuln_type, pattern in self.JS_PATTERNS.items():
            regex = re.compile(pattern)
            
            for i, line in enumerate(self.lines):
                if regex.search(line):
                    description = self._get_js_description(vuln_type)
                    fix = self._get_js_fix(vuln_type)
                    severity = self._get_js_severity(vuln_type)
                    
                    vulnerabilities.append(
                        SecurityVulnerability(
                            vuln_type,
                            i + 1,
                            description,
                            line.strip(),
                            self.file_path,
                            fix,
                            severity
                        )
                    )
        
        # Check for missing propTypes in React components (if React is being used)
        if self.language in ['react', 'react_typescript'] and 'react' in self.frameworks:
            component_matches = re.finditer(r'(?:class\s+(\w+)\s+extends\s+(?:React\.)?Component|function\s+(\w+)\s*\([^)]*\)\s*\{|const\s+(\w+)\s*=\s*(?:React\.memo\()?(?:\([^)]*\)|function)\s*(?:=>|\{))', self.code_content)
            
            for match in component_matches:
                component_name = match.group(1) or match.group(2) or match.group(3)
                if component_name and not re.search(rf'{component_name}\.propTypes', self.code_content):
                    line_number = self._get_line_number_for_match(match)
                    vulnerabilities.append(
                        SecurityVulnerability(
                            "react_missing_proptypes",
                            line_number,
                            f"React component '{component_name}' is missing PropTypes validation.",
                            self.lines[line_number-1].strip(),
                            self.file_path,
                            "Add PropTypes validation to ensure type safety of props.",
                            "medium"
                        )
                    )
        
        return vulnerabilities
    
    def _get_line_number_for_match(self, match) -> int:
        """Get line number for a regex match."""
        # Count newlines in the string up to the match start
        return self.code_content[:match.start()].count('\n') + 1
    
    def _get_js_description(self, vulnerability_type: str) -> str:
        """Get a description for a JavaScript vulnerability type."""
        descriptions = {
            "react_dangerous_html": "Use of dangerouslySetInnerHTML in React can lead to XSS vulnerabilities.",
            "react_no_prop_types": "Missing PropTypes validation can lead to type-related errors.",
            "insecure_innerhtml": "Direct manipulation of innerHTML can lead to XSS vulnerabilities.",
            "eval_usage": "Use of eval() or new Function() can lead to code injection vulnerabilities.",
            "document_write": "Use of document.write() can lead to XSS vulnerabilities.",
            "href_javascript": "JavaScript in href attributes can lead to XSS vulnerabilities.",
            "insecure_localstorage": "Storing non-JSON data in localStorage can lead to injection vulnerabilities.",
            "insecure_authentication": "Storing authentication data in localStorage is insecure.",
            "insecure_random_js": "Math.random() is not cryptographically secure.",
            "postmessage_wildcard": "Using * with postMessage allows any origin to receive the message.",
            "dom_xss": "Setting innerHTML without sanitization can lead to XSS vulnerabilities.",
        }
        
        return descriptions.get(vulnerability_type, f"Potential security issue: {vulnerability_type}")
    
    def _get_js_fix(self, vulnerability_type: str) -> str:
        """Get a fix recommendation for a JavaScript vulnerability type."""
        fixes = {
            "react_dangerous_html": "Use a sanitization library like DOMPurify before using dangerouslySetInnerHTML.",
            "react_no_prop_types": "Add PropTypes validation or use TypeScript for type safety.",
            "insecure_innerhtml": "Use textContent instead, or sanitize input with DOMPurify.",
            "eval_usage": "Avoid eval(). Use alternative approaches like JSON.parse() for JSON data.",
            "document_write": "Manipulate the DOM using safer methods like appendChild() or innerHTML with sanitized content.",
            "href_javascript": "Remove JavaScript from href attributes and use event handlers instead.",
            "insecure_localstorage": "Use JSON.stringify() and JSON.parse() for storing and retrieving data.",
            "insecure_authentication": "Use secure, HTTPOnly cookies for authentication instead of localStorage.",
            "insecure_random_js": "Use crypto.getRandomValues() for cryptographically secure random values.",
            "postmessage_wildcard": "Specify the target origin explicitly instead of using '*'.",
            "dom_xss": "Sanitize content with DOMPurify before insertion into DOM.",
        }
        
        return fixes.get(vulnerability_type, "Review and fix according to secure coding guidelines.")
    
    def _get_js_severity(self, vulnerability_type: str) -> str:
        """Get severity level for a JavaScript vulnerability type."""
        severities = {
            "react_dangerous_html": "high",
            "insecure_innerhtml": "high",
            "eval_usage": "critical",
            "dom_xss": "high",
            "insecure_authentication": "high",
            "document_write": "medium",
            "href_javascript": "medium",
            "postmessage_wildcard": "medium",
            "react_no_prop_types": "low",
            "insecure_localstorage": "medium",
            "insecure_random_js": "low",
        }
        
        return severities.get(vulnerability_type, "medium")
    
    def _check_patterns(self) -> List[SecurityVulnerability]:
        """Check for security vulnerability patterns using regex."""
        vulnerabilities = []
        
        # Use language-appropriate patterns
        patterns = self.SECURITY_PATTERNS
        if self.language in ['javascript', 'react', 'react_typescript', 'typescript']:
            patterns = {**patterns, **self.JS_PATTERNS}
        
        for vulnerability_type, pattern in patterns.items():
            regex = re.compile(pattern)
            
            for i, line in enumerate(self.lines):
                if regex.search(line):
                    severity = "high" if vulnerability_type in ["command_injection", "sql_injection", "eval_usage"] else "medium"
                    vulnerabilities.append(
                        SecurityVulnerability(
                            vulnerability_type,
                            i + 1,
                            self._get_description(vulnerability_type),
                            line.strip(),
                            self.file_path,
                            self._get_fix(vulnerability_type),
                            severity
                        )
                    )
        
        return vulnerabilities
    
    def _get_description(self, vulnerability_type: str) -> str:
        """Get a description for a vulnerability type."""
        descriptions = {
            "command_injection": "Potential command injection vulnerability. User input may be executed as a system command.",
            "sql_injection": "Potential SQL injection vulnerability. User input should be parameterized.",
            "path_traversal": "Potential path traversal vulnerability. User input should be validated.",
            "insecure_deserialization": "Insecure deserialization detected. Validate data before deserializing.",
            "hardcoded_credentials": "Hardcoded credentials detected. Use environment variables instead.",
            "insecure_random": "Use of potentially insecure random number generation. Use secrets module for security-sensitive operations.",
            "debug_enabled": "Debug mode enabled in production code. Disable in production environments.",
            "insecure_crypto": "Use of insecure cryptographic algorithm. Use modern algorithms instead.",
            "insecure_file_permissions": "Insecure file permissions detected. Restrict permissions appropriately.",
            "eval_usage": "Dangerous eval() usage detected. Avoid eval for security-sensitive operations.",
            "xxe_vulnerability": "Potential XML External Entity (XXE) vulnerability. Use safe XML parsing.",
            "cors_wildcard": "CORS wildcard detected. Specify allowed origins explicitly.",
            "unsafe_yaml": "Unsafe YAML loading detected. Use yaml.safe_load() instead.",
            "unsafe_regex": "Potentially unsafe regex usage. Validate inputs strictly.",
            "dangerous_redirect": "Potentially dangerous redirect. Validate redirect URLs.",
        }
        
        return descriptions.get(vulnerability_type, f"Potential security issue: {vulnerability_type}")
    
    def _get_fix(self, vulnerability_type: str) -> str:
        """Get a fix recommendation for a vulnerability type."""
        fixes = {
            "command_injection": "Use secure alternatives like subprocess.run() with shell=False and avoid passing user input directly to shell commands.",
            "sql_injection": "Use parameterized queries or ORM to prevent SQL injection.",
            "path_traversal": "Validate file paths against a whitelist or use os.path.abspath() and os.path.normpath() to validate paths.",
            "insecure_deserialization": "For pickle/yaml, validate input before deserializing or use safer formats like JSON.",
            "hardcoded_credentials": "Move credentials to environment variables or a secure configuration manager.",
            "insecure_random": "Use the 'secrets' module instead of 'random' for security-sensitive operations.",
            "debug_enabled": "Ensure DEBUG is set to False in production environments.",
            "insecure_crypto": "Use modern cryptographic algorithms like SHA-256 instead of MD5/SHA1.",
            "insecure_file_permissions": "Use more restrictive permissions like 0o600 for sensitive files.",
            "eval_usage": "Avoid using eval(). Consider safer alternatives based on your specific use case.",
            "xxe_vulnerability": "Disable DTD processing in XML parsers to prevent XXE attacks.",
            "cors_wildcard": "Specify allowed origins explicitly instead of using wildcard '*'.",
            "unsafe_yaml": "Use yaml.safe_load() instead of yaml.load() to prevent code execution.",
            "unsafe_regex": "Validate and sanitize user input before using in regex expressions.",
            "dangerous_redirect": "Validate redirect URLs against a whitelist of allowed destinations.",
        }
        
        return fixes.get(vulnerability_type, "Review and fix according to secure coding guidelines.")

class CodeFixer:
    """Fixes security vulnerabilities in code using AI assistance."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4-turbo"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass it explicitly.")
        
        self.client = OpenAI(api_key=self.api_key)
        self.model = model
    
    def fix_vulnerabilities(self, file_path: str, code_content: str, vulnerabilities: List[SecurityVulnerability], 
                            project_context: str = "", user_prompt: str = "") -> str:
        """
        Fix security vulnerabilities in the code using AI.
        
        Args:
            file_path: Path to the file being analyzed
            code_content: Original code content
            vulnerabilities: List of detected vulnerabilities
            project_context: Context about the project structure
            user_prompt: Optional user prompt for specific fixes
            
        Returns:
            Fixed code content
        """
        if not vulnerabilities:
            return code_content
        
        # Prepare the prompt for the AI
        file_name = os.path.basename(file_path)
        language = os.path.splitext(file_path)[1].lstrip('.')
        
        vuln_descriptions = "\n".join([
            f"- Line {v.line_number} ({v.vulnerability_type} - {v.severity}): {v.description}\n  Code: {v.code_snippet}"
            for v in vulnerabilities
        ])
        
        system_message = """
        You are a security-focused code reviewer and fixer. Your task is to analyze code with security vulnerabilities
        and fix them while maintaining the original functionality. Focus on securing the code against common attacks
        and following best practices for secure coding. Explain your changes clearly.
        """
        
        user_message = f"""
        I need to fix security issues in this {language} file: {file_name}
        
        {project_context if project_context else ""}
        
        The following security vulnerabilities were detected:
        {vuln_descriptions}
        
        {"Additional instructions: " + user_prompt if user_prompt else ""}
        
        Original code:
        ```{language}
        {code_content}
        ```
        
        Please provide:
        1. A fixed version of the entire code with all security issues addressed
        2. Brief explanations of the changes you made to fix each issue
        
        Return ONLY the fixed code without any additional commentary or explanations at the beginning or end.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.2,
                max_tokens=4000
            )
            
            fixed_code = response.choices[0].message.content
            
            # Extract only the code from the response (remove any explanations)
            # Extract only the code from the response (remove any explanations)
            code_pattern = re.compile(r'```(?:\w+)?\s*([\s\S]+?)\s*```')
            code_match = code_pattern.search(fixed_code)
            
            if code_match:
                return code_match.group(1)
            return fixed_code
            
        except Exception as e:
            print(f"Error while fixing code: {e}")
            return code_content
    
    def fix_project(self, project_path: str, vulnerabilities_by_file: Dict[str, List[SecurityVulnerability]], 
                   project_context: str, user_prompt: str = "") -> Dict[str, str]:
        """
        Fix vulnerabilities across an entire project.
        
        Args:
            project_path: Path to the project directory
            vulnerabilities_by_file: Dictionary mapping file paths to vulnerabilities
            project_context: Context about the project structure
            user_prompt: Optional user prompt for specific fixes
            
        Returns:
            Dictionary mapping file paths to fixed code
        """
        fixed_code_by_file = {}
        
        for file_path, vulnerabilities in vulnerabilities_by_file.items():
            if not vulnerabilities:
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code_content = f.read()
                
                fixed_code = self.fix_vulnerabilities(
                    file_path, 
                    code_content, 
                    vulnerabilities, 
                    project_context, 
                    user_prompt
                )
                
                fixed_code_by_file[file_path] = fixed_code
                
            except Exception as e:
                print(f"Error fixing vulnerabilities in {file_path}: {e}")
        
        return fixed_code_by_file

class SecurityDependencyChecker:
    """Checks for security issues in project dependencies."""
    
    def __init__(self, project_path: str):
        self.project_path = project_path
        
    def check_npm_dependencies(self) -> List[Dict]:
        """Check for vulnerabilities in npm dependencies using npm audit."""
        vulnerabilities = []
        
        package_json_path = os.path.join(self.project_path, "package.json")
        if not os.path.exists(package_json_path):
            return vulnerabilities
        
        try:
            # Create a temporary directory for npm audit
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy package.json to temp directory
                import shutil
                shutil.copy2(package_json_path, os.path.join(temp_dir, "package.json"))
                
                # If package-lock.json exists, copy it too
                lock_path = os.path.join(self.project_path, "package-lock.json")
                if os.path.exists(lock_path):
                    shutil.copy2(lock_path, os.path.join(temp_dir, "package-lock.json"))
                
                # Run npm audit
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0 and result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        if "vulnerabilities" in audit_data:
                            for module, info in audit_data["vulnerabilities"].items():
                                vulnerabilities.append({
                                    "module": module,
                                    "severity": info.get("severity", "unknown"),
                                    "description": info.get("overview", "No description"),
                                    "fix": info.get("recommendation", "Update the package")
                                })
                    except json.JSONDecodeError:
                        print("Error parsing npm audit output")
        
        except Exception as e:
            print(f"Error checking npm dependencies: {e}")
        
        return vulnerabilities
    
    def check_pip_dependencies(self) -> List[Dict]:
        """Check for vulnerabilities in Python dependencies using safety."""
        vulnerabilities = []
        
        requirements_path = os.path.join(self.project_path, "requirements.txt")
        if not os.path.exists(requirements_path):
            return vulnerabilities
        
        try:
            # Check if safety is installed
            try:
                subprocess.run(["safety", "--version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("Safety not installed. Install with 'pip install safety'")
                return vulnerabilities
            
            # Run safety check
            result = subprocess.run(
                ["safety", "check", "-r", requirements_path, "--json"],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                try:
                    safety_data = json.loads(result.stdout)
                    for vuln in safety_data["vulnerabilities"]:
                        vulnerabilities.append({
                            "module": vuln[0],
                            "severity": "high",  # Safety doesn't provide severity levels
                            "description": vuln[3],
                            "fix": f"Update {vuln[0]} to a version later than {vuln[2]}"
                        })
                except json.JSONDecodeError:
                    print("Error parsing safety output")
                
        except Exception as e:
            print(f"Error checking pip dependencies: {e}")
        
        return vulnerabilities

def generate_report(project_path: str, vulnerabilities_by_file: Dict[str, List[SecurityVulnerability]], 
                   dependency_vulnerabilities: List[Dict], fixed_code_by_file: Dict[str, str] = None) -> Dict:
    """Generate a detailed report of the analysis and fixes."""
    
    total_vulnerabilities = sum(len(vulns) for vulns in vulnerabilities_by_file.values())
    
    # Count vulnerabilities by severity
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vulns in vulnerabilities_by_file.values():
        for vuln in vulns:
            severity_count[vuln.severity] += 1
    
    # Count vulnerabilities by type
    type_count = {}
    for vulns in vulnerabilities_by_file.values():
        for vuln in vulns:
            type_count[vuln.vulnerability_type] = type_count.get(vuln.vulnerability_type, 0) + 1
    
    # File details
    file_details = {}
    for file_path, vulns in vulnerabilities_by_file.items():
        rel_path = os.path.relpath(file_path, project_path)
        
        file_details[rel_path] = {
            "vulnerabilities_count": len(vulns),
            "vulnerabilities": [v.to_dict() for v in vulns],
            "fixed": file_path in fixed_code_by_file if fixed_code_by_file else False
        }
    
    return {
        "project": project_path,
        "timestamp": str(os.path.getmtime(project_path)),
        "summary": {
            "total_vulnerabilities": total_vulnerabilities,
            "by_severity": severity_count,
            "by_type": type_count
        },
        "files": file_details,
        "dependency_vulnerabilities": dependency_vulnerabilities
    }

def display_vulnerabilities(vulnerabilities_by_file: Dict[str, List[SecurityVulnerability]], project_path: str):
    """Display detected vulnerabilities in a user-friendly format."""
    total_count = sum(len(vulns) for vulns in vulnerabilities_by_file.values())
    
    if total_count == 0:
        print("✅ No security vulnerabilities detected!")
        return
    
    print(f"\n🚨 Found {total_count} potential security issues across {len(vulnerabilities_by_file)} files:\n")
    
    # Group by severity for better visibility
    severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    all_vulnerabilities = []
    
    for file_path, vulns in vulnerabilities_by_file.items():
        rel_path = os.path.relpath(file_path, project_path)
        for vuln in vulns:
            all_vulnerabilities.append((rel_path, vuln))
    
    # Sort by severity (critical first)
    all_vulnerabilities.sort(key=lambda x: severity_order.get(x[1].severity, 5))
    
    for i, (file_path, vuln) in enumerate(all_vulnerabilities, 1):
        severity_marker = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵"
        }.get(vuln.severity, "⚪")
        
        print(f"{i}. {severity_marker} [{vuln.severity.upper()}] {file_path}:Line {vuln.line_number} - {vuln.vulnerability_type}")
        print(f"   Description: {vuln.description}")
        print(f"   Code: {vuln.code_snippet}")
        if vuln.recommended_fix:
            print(f"   Suggestion: {vuln.recommended_fix}")
        print()

def save_fixed_code(fixed_code_by_file: Dict[str, str], backup: bool = True):
    """Save fixed code to files, optionally creating backups."""
    for file_path, fixed_code in fixed_code_by_file.items():
        if backup:
            backup_path = f"{file_path}.bak"
            try:
                import shutil
                shutil.copy2(file_path, backup_path)
                print(f"✅ Created backup at {backup_path}")
            except Exception as e:
                print(f"⚠️ Warning: Could not create backup for {file_path}: {e}")
        
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(fixed_code)
            print(f"✅ Fixed code saved to {file_path}")
        except Exception as e:
            print(f"❌ Error saving fixed code to {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description='Analyze and fix security vulnerabilities in code projects.')
    parser.add_argument('path', help='Path to the code file or project directory to analyze')
    parser.add_argument('--fix', action='store_true', help='Fix detected vulnerabilities')
    parser.add_argument('--prompt', type=str, default='', help='Custom prompt to guide the fixing process')
    parser.add_argument('--backup', action='store_true', help='Create backups before fixing')
    parser.add_argument('--report', action='store_true', help='Generate a detailed JSON report')
    parser.add_argument('--report-file', type=str, help='Path to save the report (default: security_report.json)')
    parser.add_argument('--include', type=str, nargs='+', help='File patterns to include (default: *.py *.js *.jsx *.ts *.tsx *.php *.java)')
    parser.add_argument('--exclude', type=str, nargs='+', help='File patterns to exclude (default: *node_modules/* *venv/* *dist/* *build/* *.git/*)')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies for vulnerabilities')
    parser.add_argument('--api-key', type=str, help='OpenAI API key (defaults to OPENAI_API_KEY env var)')
    parser.add_argument('--model', type=str, default='gpt-4-turbo', help='OpenAI model to use (default: gpt-4-turbo)')
    
    args = parser.parse_args()
    
    # Check if path exists
    if not os.path.exists(args.path):
        print(f"❌ Error: Path not found: {args.path}")
        return 1
    
    # Determine if it's a file or directory
    is_file = os.path.isfile(args.path)
    
    if is_file:
        print(f"🔍 Analyzing file {args.path} for security vulnerabilities...")
        analyzer = CodeAnalyzer(args.path)
        vulnerabilities = analyzer.analyze()
        vulnerabilities_by_file = {args.path: vulnerabilities} if vulnerabilities else {}
        project_context = ""
    else:
        print(f"🔍 Analyzing project directory {args.path} for security vulnerabilities...")
        project_analyzer = ProjectAnalyzer(
            args.path, 
            include_patterns=args.include, 
            exclude_patterns=args.exclude
        )
        vulnerabilities_by_file = project_analyzer.analyze()
        project_context = project_analyzer.generate_project_context()
        print(f"Found {sum(len(v) for v in vulnerabilities_by_file.values())} vulnerabilities in {len(vulnerabilities_by_file)} files")
    
    # Check dependencies if requested
    dependency_vulnerabilities = []
    if args.check_deps and not is_file:
        print("\n📦 Checking dependencies for vulnerabilities...")
        dep_checker = SecurityDependencyChecker(args.path)
        
        npm_vulns = dep_checker.check_npm_dependencies()
        if npm_vulns:
            print(f"Found {len(npm_vulns)} vulnerable npm packages")
            dependency_vulnerabilities.extend(npm_vulns)
        
        pip_vulns = dep_checker.check_pip_dependencies()
        if pip_vulns:
            print(f"Found {len(pip_vulns)} vulnerable pip packages")
            dependency_vulnerabilities.extend(pip_vulns)
    
    # Display vulnerabilities
    display_vulnerabilities(vulnerabilities_by_file, args.path if not is_file else os.path.dirname(args.path))
    
    fixed_code_by_file = {}
    
    # Fix vulnerabilities if requested
    if args.fix and vulnerabilities_by_file:
        print("\n🔧 Fixing security vulnerabilities...")
        
        try:
            fixer = CodeFixer(api_key=args.api_key, model=args.model)
            
            if is_file:
                with open(args.path, 'r', encoding='utf-8') as f:
                    original_code = f.read()
                fixed_code = fixer.fix_vulnerabilities(
                    args.path, 
                    original_code, 
                    vulnerabilities_by_file[args.path], 
                    project_context, 
                    args.prompt
                )
                fixed_code_by_file[args.path] = fixed_code
            else:
                fixed_code_by_file = fixer.fix_project(
                    args.path,
                    vulnerabilities_by_file,
                    project_context,
                    args.prompt
                )
            
            # Save fixed code
            save_fixed_code(fixed_code_by_file, args.backup)
            
        except Exception as e:
            print(f"❌ Error during fixing: {e}")
    
    # Generate report if requested
    if args.report:
        report_data = generate_report(
            args.path, 
            vulnerabilities_by_file, 
            dependency_vulnerabilities, 
            fixed_code_by_file
        )
        
        report_file = args.report_file or (
            f"{os.path.splitext(args.path)[0]}_security_report.json" if is_file else 
            os.path.join(args.path, "security_report.json")
        )
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            print(f"📊 Report saved to {report_file}")
        except Exception as e:
            print(f"❌ Error saving report: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())