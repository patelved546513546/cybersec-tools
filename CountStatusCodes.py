def count_status_codes(filename):
    # Include common HTTP status codes
    status_codes = ["200", "301", "403", "404", "500"]
    status_counts = {code: 0 for code in status_codes}

    with open(filename, 'r') as file:
        for line in file:
            for code in status_codes:
                if f' {code} ' in line:
                    status_counts[code] += 1

    print("\n--- Status Code Counts ---")
    for code, count in status_counts.items():
        print(f"{code}: {count}")

# Run the function
count_status_codes("access.log")
