import sqlite3

def save_to_database(alerts, target):
    # Connect to the database
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()

    # Create a table if it doesn’t exist
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (id INTEGER PRIMARY KEY, target TEXT, vulnerability TEXT, severity TEXT)''')

    # Save each alert to the table
    for alert in alerts:
        c.execute("INSERT INTO scans (target, vulnerability, severity) VALUES (?, ?, ?)",
                  (target, alert['alert'], alert['risk']))

    # Save changes and close the connection
    conn.commit()
    conn.close()
    print("Scan results saved to database!")