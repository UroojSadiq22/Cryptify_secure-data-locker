import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # user table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,         -- 'encrypt' or 'decrypt'
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')


    # Encrypted data table
    c.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_data (
            user_id INTEGER,
            data TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username=? AND password=?', (username, password))
    row = c.fetchone()
    conn.close()
    if row:
        return True
    return False

def log_action(username: str, action: str):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO logs (username, action) VALUES (?, ?)", (username, action))
    conn.commit()
    conn.close()

def get_user_logs(username: str):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        SELECT action, COUNT(*) 
        FROM logs 
        WHERE username = ? 
        GROUP BY action
    """, (username,))
    action_counts = dict(c.fetchall())

    c.execute("""
        SELECT strftime('%w', timestamp) as weekday, action, COUNT(*) 
        FROM logs 
        WHERE username = ? 
        GROUP BY weekday, action
    """, (username,))
    raw_week_data = c.fetchall()
    conn.close()

    # Format data for charting
    week_days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
    week_data = {day: {"encrypt": 0, "decrypt": 0} for day in week_days}
    for wd, action, count in raw_week_data:
        day = week_days[int(wd)]
        week_data[day][action] = count

    return action_counts, week_data


def update_username(username, new_username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, username))
    conn.commit()
    conn.close()
    return True

def update_password(username, new_password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
    conn.commit()
    conn.close()
    return True
