import re
import sys
import os

def get_log_file_path(param_number):
    if len(sys.argv) <= param_number:
        print("Error: No log file path provided.")
        sys.exit(1)
    log_file_path = sys.argv[param_number]
    if not os.path.exists(log_file_path):
        print("Error: The log file does not exist.")
        sys.exit(1)
    return log_file_path

def filter_log_records(log_file_path, regex, case_sensitive=False, print_records=False, print_summary=False):
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(regex, flags)
    matching_records = []

    with open(log_file_path, 'r') as file:
        for line in file:
            if pattern.search(line):
                matching_records.append(line)
                if print_records:
                    print(line.strip())

    if print_summary:
        print(f"The log file contains {len(matching_records)} records that match the regex \"{regex}\" with case-sensitive set to {case_sensitive}.")
    
    return matching_records

def main():
    log_file_path = get_log_file_path(1)

    # Step 5: Investigate the gateway firewall log for 'sshd' records
    print("Investigating 'sshd' records...")
    sshd_records = filter_log_records(log_file_path, 'sshd', case_sensitive=False, print_records=True, print_summary=True)

    # Step 5: Investigate for 'invalid user' records
    print("\nInvestigating 'invalid user' records...")
    invalid_user_records = filter_log_records(log_file_path, 'invalid user', case_sensitive=False, print_records=True, print_summary=True)

    # Step 5: Investigate for 'invalid user.*220.195.35.40' records
    print("\nConfirming invalid user attempts from IP 220.195.35.40...")
    invalid_user_ip_records = filter_log_records(log_file_path, 'invalid user.*220.195.35.40', case_sensitive=False, print_records=True, print_summary=True)

    # Step 5: Investigate for 'error' records
    print("\nInvestigating 'error' records...")
    error_records = filter_log_records(log_file_path, 'error', case_sensitive=False, print_records=True, print_summary=True)

if __name__ == "__main__":
    main()
