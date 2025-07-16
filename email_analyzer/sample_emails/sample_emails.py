import os
def create_legitimate_email():
	"""create a legitimate email sample"""
	email_content="""Return-path:<support@paypal.com>
	Delivered-To: user@example.com
Received: from mail.paypal.com (mail.paypal.com [66.211.169.66])
    by mx.google.com with ESMTPS id abc123
    for <user@example.com>; Mon, 15 Jan 2024 10:30:00 -0800
Received: from internal.paypal.com (internal.paypal.com [10.0.0.1])
    by mail.paypal.com with ESMTP id xyz789
    for <user@example.com>; Mon, 15 Jan 2024 10:29:58 -0800
From: PayPal Support <support@paypal.com>
To: user@example.com
Subject: Your Account Statement
Date: Mon, 15 Jan 2024 10:29:58 -0800
Message-ID: <20240115102958.ABC123@paypal.com>
Authentication-Results: mx.google.com;
    spf=pass (google.com: domain of support@paypal.com designates 66.211.169.66 as permitted sender);
    dkim=pass header.i=@paypal.com;
    dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=paypal.com
X-Mailer: PayPal Email System v2.1
Content-Type: text/plain; charset=utf-8

Dear Customer,

Your monthly account statement is ready for review.

Best regards,
PayPal Support Team
"""
	with open('sample_emails/legitimate_email.eml','w')as f:
		f.write(email_content)
	print(" created legitimate_email.eml")

def create_spoofed_email():
	"""create a spoofed email sample"""
	email_content="""return-path:,no-reply@suspicious-domain.com>
Delivered-To: user@example.com
Received: from mail.suspicious-domain.com (suspicious-domain.com [185.234.219.89])
    by mx.google.com with ESMTPS id def456
    for <user@example.com>; Mon, 15 Jan 2024 14:45:00 -0800
From: PayPal Security <security@paypal.com>
To: user@example.com
Subject: URGENT: Account Suspended - Verify Now
Date: Mon, 15 Jan 2024 14:45:00 -0800
Message-ID: <20240115144500.DEF456@suspicious-domain.com>
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain of security@paypal.com does not designate 185.234.219.89 as permitted sender);
    dkim=fail header.i=@paypal.com;
    dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=paypal.com
X-Mailer: PHP Mail v5.4
Content-Type: text/html; charset=utf-8

<html>
<body>
<h2>Account Suspended!</h2>
<p>Click here to verify: <a href="http://paypal-security.suspicious-domain.com/verify">Verify Account</a></p>
</body>
</html>
"""
	with open('sample_emails/spoofed_emails.eml','w')as f:
		f.write(email_content)
	print("created spoofed_email.eml")

def create_malformed_email():
	"""create an email eith malformed headers"""
	email_content="""Return-Path:<attacker@evil.com>
Delivered-To: user@example.com
Received: from [192.168.1.100] (unknown [203.0.113.1])
    by mx.google.com with ESMTP id ghi789
    for <user@example.com>; Mon, 15 Jan 2024 16:20:00 -0800
From: "Bank Manager" <manager@legitimate-bank.com>
To: user@example.com
Subject: =?utf-8?B?8J+RjSBCYW5rIE5vdGlmaWNhdGlvbg==?=
Date: Mon, 15 Jan 2024 16:20:00 -0800
Message-ID: <invalid-message-id>
Authentication-Results: mx.google.com;
    spf=neutral (google.com: 203.0.113.1 is neither permitted nor denied);
    dkim=none;
    dmarc=none
X-Mailer: 
Content-Type: text/plain; charset=utf-8

Urgent banking notification...
"""
	with open('sample_emails/malformed_email.eml','w')as f:
		f.write(email_content)
	print("created malformed_email.eml")
if __name__=="__main__":
	os.makedirs('sample_emails', exist_ok=True)
	create_legitimate_email()
	create_spoofed_email()
	create_malformed_email()
	print("sample email files created sccessfully!")
