import hashlib
import os


def calculate_hash(filename):
    sha256 = hashlib.sha256()

    try:
        with open(filename, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except Exception as e:
        print(f"Error hashing file: {e}")
        return None


def file_exists(filename):
    return os.path.isfile(filename)