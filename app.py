from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here_replace_this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///customers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminPasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Change Password')

# Helper - Check admin login
def is_admin_logged_in():
    return session.get('admin_logged_in')

# Routes

# Employee area (no login)
@app.route('/', methods=['GET', 'POST'])
def employee_area():
    search_query = request.args.get('search', '')
    if search_query:
        customers = Customer.query.filter(Customer.name.ilike(f'%{search_query}%')).order_by(Customer.date_added.desc()).all()
    else:
        customers = Customer.query.order_by(Customer.date_added.desc()).all()

    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            expiry = datetime.utcnow() + timedelta(days=60)
            new_customer = Customer(name=name.strip(), expiry_date=expiry)
            db.session.add(new_customer)
            db.session.commit()
            flash('Customer added successfully!', 'success')
            return redirect(url_for('employee_area'))
        else:
            flash('Please enter a customer name.', 'danger')

    return render_template('employee.html', customers=customers, search_query=search_query)

# Employee edit customer (no delete)
@app.route('/edit/<int:customer_id>', methods=['GET', 'POST'])
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            customer.name = name.strip()
            db.session.commit()
            flash('Customer updated successfully!', 'success')
            return redirect(url_for('employee_area'))
        else:
            flash('Name cannot be empty.', 'danger')
    return render_template('edit_customer.html', customer=customer)

# Admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if is_admin_logged_in():
        return redirect(url_for('admin_area'))

    form = LoginForm()
    if form.validate_on_submit():
        admin = AdminUser.query.filter_by(username=form.username.data).first()
        if admin and admin.check_password(form.password.data):
            session['admin_logged_in'] = True
            flash('Logged in successfully.', 'success')
            return redirect(url_for('admin_area'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('admin_login.html', form=form)

# Admin logout
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out.', 'info')
    return redirect(url_for('admin_login'))

# Admin area
@app.route('/admin', methods=['GET', 'POST'])
def admin_area():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    search_query = request.args.get('search', '')
    if search_query:
        customers = Customer.query.filter(Customer.name.ilike(f'%{search_query}%')).order_by(Customer.date_added.desc()).all()
    else:
        customers = Customer.query.order_by(Customer.date_added.desc()).all()

    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            expiry = datetime.utcnow() + timedelta(days=60)
            new_customer = Customer(name=name.strip(), expiry_date=expiry)
            db.session.add(new_customer)
            db.session.commit()
            flash('Customer added successfully!', 'success')
            return redirect(url_for('admin_area'))
        else:
            flash('Please enter a customer name.', 'danger')

    return render_template('admin.html', customers=customers, search_query=search_query)

# Admin edit customer (with delete)
@app.route('/admin/edit/<int:customer_id>', methods=['GET', 'POST'])
def admin_edit_customer(customer_id):
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    customer = Customer.query.get_or_404(customer_id)

    if request.method == 'POST':
        if 'delete' in request.form:
            db.session.delete(customer)
            db.session.commit()
            flash('Customer deleted.', 'warning')
            return redirect(url_for('admin_area'))
        else:
            name = request.form.get('name')
            if name:
                customer.name = name.strip()
                db.session.commit()
                flash('Customer updated successfully!', 'success')
                return redirect(url_for('admin_area'))
            else:
                flash('Name cannot be empty.', 'danger')

    return render_template('admin_edit_customer.html', customer=customer)

# Admin change password
@app.route('/admin/change-password', methods=['GET', 'POST'])
def admin_change_password():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    form = AdminPasswordChangeForm()
    admin = AdminUser.query.filter_by(username='admin').first()

    if form.validate_on_submit():
        if admin.check_password(form.current_password.data):
            admin.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('admin_area'))
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('admin_change_password.html', form=form)

# Initialize admin user on first run
@app.before_first_request
def create_tables():
    db.create_all()
    admin = AdminUser.query.filter_by(username='admin').first()
    if not admin:
        admin = AdminUser(username='admin')
        admin.set_password('admin123')  # initial password, change it ASAP
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

