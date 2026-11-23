from hasher import calculate_hash

file = "test.txt"

hash_value = calculate_hash(file)

print("SHA-256:")
print(hash_value)