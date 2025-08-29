import re
import json
import logging
from vulnerability_rules import PHPVulnerabilityRules, JSVulnerabilityRules

class SecurityAnalyzer:
    def __init__(self):
        self.php_rules = PHPVulnerabilityRules()
        self.js_rules = JSVulnerabilityRules()
        self.logger = logging.getLogger(__name__)
    
    def analyze_code(self, code_content, file_type):
        """
        Main analysis method that dispatches to appropriate analyzer
        """
        if file_type == 'php':
            return self._analyze_php(code_content)
        elif file_type == 'js':
            return self._analyze_javascript(code_content)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    
    def _analyze_php(self, code_content):
        """Analyze PHP code for security vulnerabilities"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('#'):
                continue
            
            # Check each vulnerability rule
            for rule in self.php_rules.get_all_rules():
                matches = rule['pattern'].finditer(line)
                for match in matches:
                    vulnerability = {
                        'type': rule['type'],
                        'severity': rule['severity'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'code': line.strip(),
                        'message': rule['message'],
                        'description': rule['description'],
                        'remediation': rule['remediation'],
                        'cwe_id': rule.get('cwe_id'),
                        'owasp_category': rule.get('owasp_category')
                    }
                    vulnerabilities.append(vulnerability)
        
        return self._generate_report(vulnerabilities, 'php')
    
    def _analyze_javascript(self, code_content):
        """Analyze JavaScript code for security vulnerabilities"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        # Pattern-based analysis
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Check each vulnerability rule
            for rule in self.js_rules.get_all_rules():
                matches = rule['pattern'].finditer(line)
                for match in matches:
                    vulnerability = {
                        'type': rule['type'],
                        'severity': rule['severity'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'code': line.strip(),
                        'message': rule['message'],
                        'description': rule['description'],
                        'remediation': rule['remediation'],
                        'cwe_id': rule.get('cwe_id'),
                        'owasp_category': rule.get('owasp_category')
                    }
                    vulnerabilities.append(vulnerability)
        
        # Try AST analysis for more complex patterns
        try:
            ast_vulnerabilities = self._analyze_js_ast(code_content)
            vulnerabilities.extend(ast_vulnerabilities)
        except Exception as e:
            self.logger.warning(f"AST analysis failed: {str(e)}")
        
        return self._generate_report(vulnerabilities, 'js')
    
    def _analyze_js_ast(self, code_content):
        """AST-based analysis for JavaScript (simplified without esprima)"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        # Look for eval-like patterns and other AST-detectable issues
        eval_pattern = re.compile(r'\beval\s*\(', re.IGNORECASE)
        settimeout_pattern = re.compile(r'setTimeout\s*\(\s*["\']', re.IGNORECASE)
        
        for line_num, line in enumerate(lines, 1):
            # Check for eval usage
            if eval_pattern.search(line):
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'critical',
                    'line': line_num,
                    'column': eval_pattern.search(line).start() + 1,
                    'code': line.strip(),
                    'message': 'Use of eval() function detected',
                    'description': 'The eval() function executes arbitrary JavaScript code and can lead to code injection vulnerabilities.',
                    'remediation': 'Avoid using eval(). Use JSON.parse() for parsing JSON, or refactor code to eliminate dynamic code execution.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
            
            # Check for setTimeout with string
            if settimeout_pattern.search(line):
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'high',
                    'line': line_num,
                    'column': settimeout_pattern.search(line).start() + 1,
                    'code': line.strip(),
                    'message': 'setTimeout with string argument detected',
                    'description': 'Using setTimeout with a string argument can lead to code injection vulnerabilities.',
                    'remediation': 'Use setTimeout with a function reference instead of a string.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
        
        return vulnerabilities
    
    def _generate_report(self, vulnerabilities, file_type):
        """Generate analysis report with scoring"""
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] += 1
            total_score += severity_weights[severity]
        
        # Calculate security score (0-100, higher is better)
        max_possible_score = 100
        security_score = max(0, max_possible_score - total_score)
        
        return {
            'file_type': file_type,
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'security_score': round(security_score, 2),
            'vulnerabilities': vulnerabilities,
            'analysis_summary': {
                'most_critical_issues': [v for v in vulnerabilities if v['severity'] == 'critical'][:5],
                'risk_level': self._calculate_risk_level(security_score),
                'recommendations': self._get_general_recommendations(severity_counts)
            }
        }
    
    def _calculate_risk_level(self, security_score):
        """Calculate overall risk level based on security score"""
        if security_score >= 80:
            return 'Low'
        elif security_score >= 60:
            return 'Medium'
        elif security_score >= 40:
            return 'High'
        else:
            return 'Critical'
    
    def _get_general_recommendations(self, severity_counts):
        """Generate general security recommendations"""
        recommendations = []
        
        if severity_counts['critical'] > 0:
            recommendations.append("Address critical vulnerabilities immediately - they pose severe security risks")
        
        if severity_counts['high'] > 0:
            recommendations.append("Fix high-severity issues as soon as possible")
        
        if severity_counts['medium'] > 0:
            recommendations.append("Review and remediate medium-severity vulnerabilities")
        
        if severity_counts['low'] > 0:
            recommendations.append("Consider addressing low-severity issues as part of routine code maintenance")
        
        if sum(severity_counts.values()) == 0:
            recommendations.append("No obvious security vulnerabilities detected. Continue following secure coding practices.")
        
        recommendations.extend([
            "Implement automated security testing in your CI/CD pipeline",
            "Regular security code reviews by experienced developers",
            "Keep dependencies and frameworks up to date",
            "Follow OWASP secure coding guidelines"
        ])
        
        return recommendations
