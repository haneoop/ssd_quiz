from flask import Flask, render_template, request, flash, redirect, url_for
import bleach
import html
import re
import validators

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

class InputValidator:
    """OWASP C5: Validate All Inputs - XSS and SQL Injection Prevention"""
    
    @staticmethod
    def detect_xss_attack(search_term):
        """
        Detect potential XSS attack patterns
        """
        if not search_term:
            return False
        
        # Common XSS patterns
        xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe.*?>',
            r'<object.*?>',
            r'<embed.*?>',
            r'<link.*?>',
            r'<meta.*?>',
            r'vbscript:',
            r'data:text/html',
            r'expression\(',
            r'<.*?onerror.*?>',
            r'<.*?onload.*?>',
            r'<.*?onclick.*?>',
            r'alert\(',
            r'confirm\(',
            r'prompt\(',
            r'document\.cookie',
            r'document\.write',
            r'eval\(',
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, search_term, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    @staticmethod
    def detect_sql_injection_attack(search_term):
        """
        Detect potential SQL injection attack patterns
        """
        if not search_term:
            return False
        
        # Common SQL injection patterns
        sql_patterns = [
            r"'.*?OR.*?'.*?'",
            r'".*?OR.*?".*?"',
            r"'.*?AND.*?'.*?'",
            r'".*?AND.*?".*?"',
            r"'.*?UNION.*?SELECT",
            r'".*?UNION.*?SELECT',
            r"'.*?DROP.*?TABLE",
            r'".*?DROP.*?TABLE',
            r"'.*?DELETE.*?FROM",
            r'".*?DELETE.*?FROM',
            r"'.*?INSERT.*?INTO",
            r'".*?INSERT.*?INTO',
            r"'.*?UPDATE.*?SET",
            r'".*?UPDATE.*?SET',
            r"'.*?EXEC.*?\(",
            r'".*?EXEC.*?\(',
            r"'.*?EXEC\s+",
            r'".*?EXEC\s+',
            r"--",
            r"/\*.*?\*/",
            r";\s*(DROP|DELETE|INSERT|UPDATE|EXEC)",
            r"'\s*(OR|AND)\s+\d+\s*=\s*\d+",
            r'"\s*(OR|AND)\s+\d+\s*=\s*\d+',
            r"'\s*(OR|AND)\s+'.*?'\s*=\s*'.*?'",
            r'"\s*(OR|AND)\s+".*?"\s*=\s*".*?"',
            r"1\s*=\s*1",
            r"0\s*=\s*0",
            r"true\s*=\s*true",
            r"false\s*=\s*false",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, search_term, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    @staticmethod
    def sanitize_search_term(search_term):
        """
        Sanitize search input to prevent XSS attacks
        Based on OWASP Top 10 Proactive Control C5
        """
        if not search_term:
            return ""
        
        # Remove any potential HTML/script tags
        clean_term = bleach.clean(search_term, tags=[], strip=True)
        
        # HTML escape any remaining special characters
        clean_term = html.escape(clean_term)
        
        return clean_term.strip()
    
    @staticmethod
    def validate_search_term(search_term):
        """
        Validate search term format and length
        """
        if not search_term:
            return False, "Search term cannot be empty"
        
        if len(search_term) > 100:
            return False, "Search term too long (max 100 characters)"
        
        return True, "Valid"

@app.route('/')
def home():
    """Default home page with search form"""
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    """Handle search form submission with XSS and SQL injection protection"""
    raw_search_term = request.form.get('search_term', '')
    
    # Check for XSS attack
    if InputValidator.detect_xss_attack(raw_search_term):
        flash("Potential XSS attack detected. Input cleared for security.", 'error')
        return redirect(url_for('home'))
    
    # Check for SQL injection attack
    if InputValidator.detect_sql_injection_attack(raw_search_term):
        flash("Potential SQL injection attack detected. Input cleared for security.", 'error')
        return redirect(url_for('home'))
    
    # Sanitize input
    sanitized_term = InputValidator.sanitize_search_term(raw_search_term)
    
    # Validate the sanitized input
    is_valid, message = InputValidator.validate_search_term(sanitized_term)
    
    if not is_valid:
        flash(f"Invalid input: {message}", 'error')
        return redirect(url_for('home'))
    
    # If input passes all security checks, go to results page
    return render_template('results.html', search_term=sanitized_term)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)