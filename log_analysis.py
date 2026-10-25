import csv
LOG_FILE = "Linux_2k.log"

# Step 1: Open and read the log file
with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
    logs = file.readlines()

# Step 2: Select lines 200–500
subset_logs = logs[199:500]

# Step 3: Search for suspicious authentication events
suspicious_entries = []

for line_number, line in enumerate(subset_logs, start=200):
    text = line.lower()

    if "failed password" in text:
        event_type = "Failed Login"
    elif "authentication failure" in text:
        event_type = "Authentication Failure"
    elif "user unknown" in text or "invalid user" in text:
        event_type = "Unknown/Invalid User"
    else:
        continue

    suspicious_entries.append(
        (line_number, event_type, line.strip())
    )

# Step 4: Display the results
print("=== Suspicious Log Entries ===")

for line_number, event_type, entry in suspicious_entries:
    print(f"Line {line_number} | {event_type} | {entry}")

print(f"\nTotal suspicious entries: {len(suspicious_entries)}")


# Step 5: Export findings to a CSV file
OUTPUT_FILE = "suspicious_logs.csv"

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Line Number", "Event Type", "Log Entry"])
    writer.writerows(suspicious_entries)

print(f"Results saved to {OUTPUT_FILE}")
