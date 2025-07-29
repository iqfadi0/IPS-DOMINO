from flask import Flask, render_template, request, redirect, session, url_for
from datetime import datetime, timedelta
import os
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATABASE = 'database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL
            )
        ''')

@app.before_first_request
def initialize():
    init_db()

# صلاحيات الباسوردات
USERS = {
    "ips@2025": "user",
    "Fadi!!@@": "admin"
}

@app.route('/', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        password = request.form.get('password')
        role = USERS.get(password)
        if role:
            session['logged_in'] = True
            session['role'] = role
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid password.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = get_db()

    # إضافة زبون
    if request.method == 'POST':
        name = request.form.get('name').strip()
        start_date = datetime.now()
        end_date = start_date + timedelta(days=60)  # شهرين
        if name:
            conn.execute("INSERT INTO customers (name, start_date, end_date) VALUES (?, ?, ?)",
                         (name, start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d")))
            conn.commit()
            return redirect(url_for('dashboard'))

    # جلب كل الزبائن للعرض
    customers = conn.execute("SELECT * FROM customers").fetchall()
    return render_template('dashboard.html', customers=customers, role=session['role'])

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = get_db()
    customer = conn.execute("SELECT * FROM customers WHERE id = ?", (id,)).fetchone()
    if not customer:
        return "Customer not found", 404

    if request.method == 'POST':
        name = request.form.get('name').strip()
        if name:
            start_date = datetime.strptime(customer['start_date'], "%Y-%m-%d")
            end_date = start_date + timedelta(days=60)
            conn.execute("UPDATE customers SET name = ?, end_date = ? WHERE id = ?", 
                         (name, end_date.strftime("%Y-%m-%d"), id))
            conn.commit()
            return redirect(url_for('dashboard'))

    return render_template('edit.html', customer=customer)

@app.route('/delete/<int:id>')
def delete(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        return "Access denied", 403

    conn = get_db()
    conn.execute("DELETE FROM customers WHERE id = ?", (id,))
    conn.commit()
    return redirect(url_for('dashboard'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    result = None
    if request.method == 'POST':
        name = request.form.get('name').strip()
        conn = get_db()
        customer = conn.execute("SELECT * FROM customers WHERE name = ?", (name,)).fetchone()
        if customer:
            result = {
                "name": customer['name'],
                "start_date": customer['start_date'],
                "end_date": customer['end_date']
            }
        else:
            result = 'No customer found with that name.'

    return render_template('search.html', result=result)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
