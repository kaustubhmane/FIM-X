import sqlite3

connection = sqlite3.connect("data/fimx.db")

cursor = connection.cursor()

cursor.execute("""
    SELECT timestamp, event_type, file_path, old_hash, new_hash
    FROM events
    ORDER BY id DESC
""")

events = cursor.fetchall()

for event in events:
    print("----------------------------------------")
    print("Time:", event[0])
    print("Event:", event[1])
    print("File:", event[2])
    print("Old Hash:", event[3])
    print("New Hash:", event[4])

connection.close()