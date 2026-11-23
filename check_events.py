import sqlite3

connection = sqlite3.connect("data/fimx.db")
cursor = connection.cursor()

cursor.execute("""
    SELECT event_type, COUNT(*)
    FROM events
    GROUP BY event_type
""")

for event, count in cursor.fetchall():
    print(f"{event}: {count}")

connection.close()