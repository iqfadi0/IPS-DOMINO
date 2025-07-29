from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'  # غيّرها بكلمة سر قوية

# كلمات السر والدور
users = {
    'admin': 'Fadi!!@@',
    'user': 'ips@2025'
}

def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS app_password (
                id INTEGER PRIMARY KEY,
                password TEXT NOT NULL
            )
        ''')
        # حط كلمة المرور الافتراضية للباسورد اللي يغيره الادمن
        c.execute("INSERT OR IGNORE INTO app_password (id, password) VALUES (1, 'Fadi!!@@')")
        conn.commit()

@app.before_first_request
def setup():
    init_db()

@app.route('/', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        password = request.form.get('password')
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM app_password WHERE id=1")
            admin_password = c.fetchone()[0]

        if password == admin_password:
            session['logged_in'] = True
            session['role'] = 'admin'
            return redirect(url_for('dashboard'))
        elif password == users['user']:
            session['logged_in'] = True
            session['role'] = 'user'
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid password'
    return render_template('login.html', error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    role = session.get('role')

    if request.method == 'POST':
        name = request.form.get('name').strip()
        if name:
            start_date = datetime.now()
            end_date = start_date + timedelta(days=60)
            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")

            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute("INSERT INTO customers (name, start_date, end_date) VALUES (?, ?, ?)",
                          (name, start_date_str, end_date_str))
                conn.commit()

    search_name = request.args.get('search_name', '').strip()

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        if search_name:
            c.execute("SELECT id, name, start_date, end_date FROM customers WHERE name LIKE ?", ('%'+search_name+'%',))
        else:
            c.execute("SELECT id, name, start_date, end_date FROM customers")
        customers = c.fetchall()

    return render_template('dashboard.html', customers=customers, role=role, search_name=search_name)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    role = session.get('role')

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        if request.method == 'POST':
            name = request.form.get('name').strip()
            end_date = request.form.get('end_date').strip()
            if name and end_date:
                c.execute("UPDATE customers SET name=?, end_date=? WHERE id=?", (name, end_date, id))
                conn.commit()
                return redirect(url_for('dashboard'))

        c.execute("SELECT id, name, start_date, end_date FROM customers WHERE id=?", (id,))
        customer = c.fetchone()

    if not customer:
        return "Customer not found", 404

    return render_template('edit.html', customer=customer, role=role)

@app.route('/delete/<int:id>')
def delete(id):
    if not session.get('logged_in') or session.get('role') != 'admin':
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("DELETE FROM customers WHERE id=?", (id,))
        conn.commit()

    return redirect(url_for('dashboard'))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return redirect(url_for('login'))

    message = ''
    if request.method == 'POST':
        new_password = request.form.get('new_password').strip()
        if new_password:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute("UPDATE app_password SET password=? WHERE id=1", (new_password,))
                conn.commit()
            message = 'Password changed successfully.'
    return render_template('change_password.html', message=message)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
