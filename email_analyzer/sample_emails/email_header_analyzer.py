# email_header_analyzer.py
import email
import re
import json
from datetime import datetime
import os

class EmailHeaderAnalyzer:
    def __init__(self):
        self.suspicious_patterns = {
            'urgent_keywords': ['urgent', 'immediate', 'suspended', 'verify now', 'act now'],
            'suspicious_domains': ['suspicious-domain.com', 'evil.com', 'phishing.net'],
            'suspicious_ips': ['185.234.219.89', '203.0.113.1'],  # Example suspicious IPs
            'suspicious_mailers': ['php mail', 'bulk mailer', 'mass mail']
        }
    
    def parse_email_file(self, file_path):
        """Parse .eml file and extract headers"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                msg = email.message_from_file(f)
            return msg
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")
            return None
    
    def extract_key_headers(self, msg):
        """Extract important headers for analysis"""
        headers = {
            'from': msg.get('From', ''),
            'reply_to': msg.get('Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'x_mailer': msg.get('X-Mailer', ''),
            'received': msg.get_all('Received') or [],
            'authentication_results': msg.get('Authentication-Results', '')
        }
        return headers
    
    def analyze_spf_dkim_dmarc(self, auth_results):
        """Analyze SPF, DKIM, DMARC authentication results"""
        if not auth_results:
            return {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
        
        auth_results = auth_results.lower()
        
        # Extract SPF result
        spf_match = re.search(r'spf=(\w+)', auth_results)
        spf_result = spf_match.group(1) if spf_match else 'none'
        
        # Extract DKIM result
        dkim_match = re.search(r'dkim=(\w+)', auth_results)
        dkim_result = dkim_match.group(1) if dkim_match else 'none'
        
        # Extract DMARC result
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
        dmarc_result = dmarc_match.group(1) if dmarc_match else 'none'
        
        return {
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result
        }
    
    def check_sender_spoofing(self, headers):
        """Check for potential sender spoofing"""
        issues = []
        
        # Extract email addresses from From and Return-Path
        from_email = self.extract_email_address(headers['from'])
        return_path_email = self.extract_email_address(headers['return_path'])
        
        # Check if From and Return-Path domains match
        if from_email and return_path_email:
            from_domain = from_email.split('@')[1] if '@' in from_email else ''
            return_path_domain = return_path_email.split('@')[1] if '@' in return_path_email else ''
            
            if from_domain != return_path_domain:
                issues.append({
                    'type': 'DOMAIN_MISMATCH',
                    'description': f'From domain ({from_domain}) != Return-Path domain ({return_path_domain})',
                    'severity': 'MEDIUM'
                })
        
        # Check authentication results
        auth_results = self.analyze_spf_dkim_dmarc(headers['authentication_results'])
        
        if auth_results['spf'] == 'fail':
            issues.append({
                'type': 'SPF_FAIL',
                'description': 'SPF authentication failed',
                'severity': 'HIGH'
            })
        
        if auth_results['dkim'] == 'fail':
            issues.append({
                'type': 'DKIM_FAIL',
                'description': 'DKIM authentication failed',
                'severity': 'HIGH'
            })
        
        if auth_results['dmarc'] == 'fail':
            issues.append({
                'type': 'DMARC_FAIL',
                'description': 'DMARC authentication failed',
                'severity': 'HIGH'
            })
        
        return issues
    
    def check_malformed_headers(self, headers):
        """Check for malformed or suspicious headers"""
        issues = []
        
        # Check Message-ID format
        message_id = headers['message_id']
        if message_id and not re.match(r'^<[^@]+@[^>]+>$', message_id):
            issues.append({
                'type': 'MALFORMED_MESSAGE_ID',
                'description': f'Invalid Message-ID format: {message_id}',
                'severity': 'MEDIUM'
            })
        
        # Check for missing essential headers
        if not headers['from']:
            issues.append({
                'type': 'MISSING_FROM',
                'description': 'Missing From header',
                'severity': 'HIGH'
            })
        
        if not headers['date']:
            issues.append({
                'type': 'MISSING_DATE',
                'description': 'Missing Date header',
                'severity': 'MEDIUM'
            })
        
        # Check X-Mailer for suspicious patterns
        x_mailer = headers['x_mailer'].lower()
        for pattern in self.suspicious_patterns['suspicious_mailers']:
            if pattern in x_mailer:
                issues.append({
                    'type': 'SUSPICIOUS_MAILER',
                    'description': f'Suspicious X-Mailer: {headers["x_mailer"]}',
                    'severity': 'MEDIUM'
                })
        
        return issues
    
    def check_suspicious_content(self, headers):
        """Check for suspicious content patterns"""
        issues = []
        
        # Check subject for urgent keywords
        subject = headers['subject'].lower()
        for keyword in self.suspicious_patterns['urgent_keywords']:
            if keyword in subject:
                issues.append({
                    'type': 'URGENT_KEYWORD',
                    'description': f'Urgent keyword in subject: "{keyword}"',
                    'severity': 'MEDIUM'
                })
        
        # Check for suspicious domains in From field
        from_email = self.extract_email_address(headers['from'])
        if from_email:
            domain = from_email.split('@')[1] if '@' in from_email else ''
            if domain in self.suspicious_patterns['suspicious_domains']:
                issues.append({
                    'type': 'SUSPICIOUS_DOMAIN',
                    'description': f'Suspicious sender domain: {domain}',
                    'severity': 'HIGH'
                })
        
        return issues
    
    def analyze_received_headers(self, received_headers):
        """Analyze the email routing path"""
        issues = []
        
        if not received_headers:
            issues.append({
                'type': 'MISSING_RECEIVED',
                'description': 'No Received headers found',
                'severity': 'HIGH'
            })
            return issues
        
        # Check for suspicious IPs in routing
        for received in received_headers:
            for suspicious_ip in self.suspicious_patterns['suspicious_ips']:
                if suspicious_ip in received:
                    issues.append({
                        'type': 'SUSPICIOUS_IP',
                        'description': f'Suspicious IP in routing: {suspicious_ip}',
                        'severity': 'HIGH'
                    })
        
        # Check for unusual number of hops
        if len(received_headers) > 10:
            issues.append({
                'type': 'EXCESSIVE_HOPS',
                'description': f'Unusual number of mail hops: {len(received_headers)}',
                'severity': 'MEDIUM'
            })
        
        return issues
    
    def extract_email_address(self, header_value):
        """Extract email address from header value"""
        if not header_value:
            return None
        
        # Look for email in angle brackets
        match = re.search(r'<([^>]+)>', header_value)
        if match:
            return match.group(1)
        
        # Look for standalone email address
        match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', header_value)
        if match:
            return match.group(1)
        
        return None
    
    def calculate_threat_score(self, all_issues):
        """Calculate overall threat score based on issues found"""
        score = 0
        for issue in all_issues:
            if issue['severity'] == 'HIGH':
                score += 3
            elif issue['severity'] == 'MEDIUM':
                score += 2
            else:
                score += 1
        
        if score >= 6:
            return 'HIGH'
        elif score >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def analyze_email(self, file_path):
        """Main analysis function"""
        print(f"\n🔍 Analyzing: {file_path}")
        print("=" * 50)
        
        # Parse email
        msg = self.parse_email_file(file_path)
        if not msg:
            return None
        
        # Extract headers
        headers = self.extract_key_headers(msg)
        
        # Perform various checks
        spoofing_issues = self.check_sender_spoofing(headers)
        malformed_issues = self.check_malformed_headers(headers)
        content_issues = self.check_suspicious_content(headers)
        routing_issues = self.analyze_received_headers(headers['received'])
        
        # Combine all issues
        all_issues = spoofing_issues + malformed_issues + content_issues + routing_issues
        
        # Calculate threat level
        threat_level = self.calculate_threat_score(all_issues)
        
        # Create analysis report
        report = {
            'file': file_path,
            'timestamp': datetime.now().isoformat(),
            'threat_level': threat_level,
            'headers': headers,
            'authentication': self.analyze_spf_dkim_dmarc(headers['authentication_results']),
            'issues': all_issues,
            'summary': {
                'total_issues': len(all_issues),
                'high_severity': len([i for i in all_issues if i['severity'] == 'HIGH']),
                'medium_severity': len([i for i in all_issues if i['severity'] == 'MEDIUM']),
                'low_severity': len([i for i in all_issues if i['severity'] == 'LOW'])
            }
        }
        
        # Display results
        self.display_analysis_results(report)
        
        return report
    
    def display_analysis_results(self, report):
        """Display analysis results in a readable format"""
        print(f"📧 Email: {os.path.basename(report['file'])}")
        print(f"🚨 Threat Level: {report['threat_level']}")
        print(f"📊 Issues Found: {report['summary']['total_issues']}")
        
        print(f"\n📋 Key Headers:")
        print(f"  From: {report['headers']['from']}")
        print(f"  Return-Path: {report['headers']['return_path']}")
        print(f"  Subject: {report['headers']['subject']}")
        print(f"  X-Mailer: {report['headers']['x_mailer']}")
        
        print(f"\n🔐 Authentication:")
        auth = report['authentication']
        print(f"  SPF: {auth['spf']}")
        print(f"  DKIM: {auth['dkim']}")
        print(f"  DMARC: {auth['dmarc']}")
        
        if report['issues']:
            print(f"\n⚠️  Issues Detected:")
            for issue in report['issues']:
                severity_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
                print(f"  {severity_emoji[issue['severity']]} {issue['type']}: {issue['description']}")
        else:
            print(f"\n✅ No issues detected")
        
        print("-" * 50)

def main():
    """Main function to analyze all sample emails"""
    analyzer = EmailHeaderAnalyzer()
    
    # Check if sample emails exist
    if not os.path.exists('sample_emails'):
        print("❌ Sample emails directory not found. Run create_sample_emails.py first!")
        return
    
    # Analyze all .eml files
    email_files = [f for f in os.listdir('sample_emails') if f.endswith('.eml')]
    
    if not email_files:
        print("❌ No .eml files found in sample_emails directory!")
        return
    
    print("🎯 Starting Email Header Analysis")
    print("=" * 50)
    
    reports = []
    for email_file in email_files:
        file_path = os.path.join('sample_emails', email_file)
        report = analyzer.analyze_email(file_path)
        if report:
            reports.append(report)
    
    # Summary
    print(f"\n📊 ANALYSIS SUMMARY")
    print("=" * 50)
    for report in reports:
        threat_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        print(f"{threat_emoji[report['threat_level']]} {os.path.basename(report['file'])}: {report['threat_level']} threat")
    
    # Save detailed report
    with open('email_analysis_report.json', 'w') as f:
        json.dump(reports, f, indent=2)
    
    print(f"\n💾 Detailed report saved to: email_analysis_report.json")

if __name__ == "__main__":
    main()
