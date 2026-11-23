
from database import get_all_files

print("\n--- SAVED BASELINE PATHS ---")

for file_path, file_hash in get_all_files():
    print(file_path)
