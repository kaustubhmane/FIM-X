
import os

from hasher import calculate_hash
from database import (
    get_file,
    get_all_files,
    set_active_alert,
    resolve_alert,
)


def check_file(file_path):
    saved_record = get_file(file_path)

    if saved_record is None:
        print(f"[NEW FILE] {file_path}")
        set_active_alert("NEW", file_path)
        return "NEW"

    saved_hash = saved_record[2]
    current_hash = calculate_hash(file_path)

    if current_hash is None:
        print(f"[ERROR] Could not hash {file_path}")
        return None

    if current_hash != saved_hash:
        print(f"[MODIFIED] {file_path}")
        print(f"Old Hash: {saved_hash}")
        print(f"New Hash: {current_hash}")

        set_active_alert(
            "MODIFIED",
            file_path,
            saved_hash,
            current_hash,
        )
        return "MODIFIED"

    resolve_alert(file_path, "File matches trusted baseline")
    print(f"[OK] {file_path}")
    return "OK"


def scan_folder(folder):
    print()
    print("===================================")
    print("Starting Integrity Scan")
    print("===================================")

    results = {
        "OK": 0,
        "MODIFIED": 0,
        "NEW": 0,
        "DELETED": 0,
    }

    current_files = set()

    # Scan all files currently present.
    for root, directories, files in os.walk(folder):
        for filename in files:
            file_path = os.path.normpath(
                os.path.join(root, filename)
            )
            current_files.add(file_path)

            try:
                result = check_file(file_path)
                if result in results:
                    results[result] += 1
            except Exception as error:
                print(f"[ERROR] {file_path}: {error}")

    # Read the trusted baseline.
    baseline_files = get_all_files()
    baseline_paths = set()

    
    for file_path, saved_hash in baseline_files:
        baseline_paths.add(os.path.normpath(file_path))


    # Detect files that existed in the baseline but are now missing.
    for file_path in baseline_paths:
        if file_path not in current_files:
            print(f"[DELETED] {file_path}")
            set_active_alert("DELETED", file_path)
            results["DELETED"] += 1

    print()
    print("===================================")
    print("Integrity Scan Completed")
    print("===================================")
    print(f"Files OK       : {results['OK']}")
    print(f"Modified       : {results['MODIFIED']}")
    print(f"New Files      : {results['NEW']}")
    print(f"Deleted Files  : {results['DELETED']}")


if __name__ == "__main__":
    folder = input("Enter folder to scan: ").strip()

    if not os.path.isdir(folder):
        print("Folder not found.")
    else:
        scan_folder(folder)
