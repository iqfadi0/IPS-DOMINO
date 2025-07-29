from flask import Flask, render_template, request, redirect, session, url_for
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

PASSWORD_FILE = 'password.txt'

def read_password():
    if not os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'w') as f:
            f.write('Fadi!!@@')  # الباسورد الافتراضي
    with open(PASSWORD_FILE, 'r') as f:
        return f.read().strip()

def write_password(new_password):
    with open(PASSWORD_FILE, 'w') as f:
        f.write(new_password.strip())

@app.route('/', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        entered_password = request.form.get('password')
        correct_password = read_password()
        if entered_password == correct_password:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid password, please try again.'
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    error = ''
    success = ''
    if request.method == 'POST':
        current_pass = request.form.get('current_password')
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')
        correct_password = read_password()

        if current_pass != correct_password:
            error = 'Current password is incorrect.'
        elif new_pass != confirm_pass:
            error = 'New password and confirmation do not match.'
        elif len(new_pass.strip()) < 4:
            error = 'New password must be at least 4 characters.'
        else:
            write_password(new_pass)
            success = 'Password changed successfully.'

    return render_template('change_password.html', error=error, success=success)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
