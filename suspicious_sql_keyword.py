with open("/var/log/apache2/access.log","r") as log_file:
	for line in log_file:
		if "OR 1=1"in line or "UNION SELECT"in line or "'--"in line:
			print(f"SQL injection pattern detected:{line.strip()}')
