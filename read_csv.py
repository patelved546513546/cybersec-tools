import csv

fail = 0
success = 0

filename = input("Enter CSV file name: ")  # user input

with open(filename) as file:
    reader = csv.DictReader(file)
    for row in reader:
        if row["status"] == "fail":
            fail += 1
        elif row["status"] == "success":
            success += 1

print(f"Failed logins: {fail}")
print(f"Successful logins: {success}")
