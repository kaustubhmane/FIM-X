import os
from datetime import datetime

from hasher import calculate_hash
from database import initialize_database, save_file


def create_baseline(folder):

    initialize_database()

    total_files = 0

    for root, directories, files in os.walk(folder):

        for filename in files:

            file_path = os.path.join(root, filename)

            try:
                file_hash = calculate_hash(file_path)

                if file_hash is None:
                    continue

                file_size = os.path.getsize(file_path)

                last_modified = datetime.fromtimestamp(
                    os.path.getmtime(file_path)
                ).isoformat()

                save_file(
                    file_path,
                    file_hash,
                    file_size,
                    last_modified
                )

                total_files += 1

                print(f"[BASELINE] {file_path}")

            except Exception as error:
                print(f"[ERROR] {file_path}: {error}")

    print()
    print("===================================")
    print("Baseline creation completed")
    print(f"Files recorded: {total_files}")
    print("===================================")


if __name__ == "__main__":

    folder = input("Enter folder to monitor: ")

    if not os.path.isdir(folder):
        print("Folder not found.")
        exit()

    create_baseline(folder)