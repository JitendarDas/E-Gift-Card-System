from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField,DecimalField, SubmitField, SelectField, DateField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, ValidationError, NumberRange
from datetime import datetime
from flask_mysqldb import MySQL
import bcrypt
import logging
import MySQLdb

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
csrf = CSRFProtect(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Spider@0205'
app.config['MYSQL_DB'] = 'mydatabase'
mysql = MySQL(app)

logging.basicConfig(level=logging.INFO)

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = SelectField('Role', choices=[('Customer', 'Customer'), ('Merchant', 'Merchant')], validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email already taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = SelectField('Role', choices=[('Customer', 'Customer'), ('Merchant', 'Merchant'),('Admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField("Login")

class GiftCardForm(FlaskForm):
    card_name = StringField('Card Name', validators=[DataRequired()])
    card_value = IntegerField('Card Value', validators=[DataRequired()])
    issue_date = DateField('Issue Date', format='%Y-%m-%d', validators=[DataRequired()])
    expiry_date = DateField('Expiry Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Submit')

class GiftCardRequestForm(FlaskForm):
    card_name = StringField('Card Name',validators=[DataRequired()])
    card_value = IntegerField('Card Value', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Request Gift Card')

class BuyGiftCardForm(FlaskForm):
    card_name = SelectField('Card Name', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Buy Gift Card')

class SellGiftCardForm(FlaskForm):
    card_name = StringField('Card Name', validators=[DataRequired()])
    card_value = IntegerField('Card Value', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Sell Gift Card')

class AccountFundingForm(FlaskForm):
    amount = DecimalField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Fund Account')
    
class CreateUserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = SelectField('Role', choices=[('Customer', 'Customer'), ('Merchant', 'Merchant')], validators=[DataRequired()])
    submit = SubmitField("Create User")

class UpdateUserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    balance = DecimalField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField("Update User")

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        role = form.role.data

        if role == 'Admin':
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
            user = cursor.fetchone()
            cursor.close()
        else:
            table_name = 'users' if role == 'Customer' else 'merchant'
            cursor = mysql.connection.cursor()
            cursor.execute(f"SELECT * FROM {table_name} WHERE email=%s", (email,))
            user = cursor.fetchone()
            cursor.close()

        print("User : ",user)
        if user:
            stored_hash = user[3]
            password_matched = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')) if stored_hash else False
            print("Password matched:", password_matched)
            if password_matched:
                session['user_id'] = user[0]
                session['role'] = role
                return redirect(url_for('dashboard'))
        
        flash("Login failed. Please check your email, password, and role.")
        return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        if role == 'Customer':
            table_name = 'users'
        elif role == 'Merchant':
            table_name = 'merchant'
        else:
            flash("Invalid role selection. Please select either 'Customer' or 'Merchant'.")
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        
        cursor = mysql.connection.cursor()
        query = f"INSERT INTO {table_name} (name, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        role = session.get('role')

        if role == 'Customer':
            table_name = 'users'
        elif role == 'Merchant':
            table_name = 'merchant'
        else :  
            role = 'Admin'
            table_name = 'admin'
        
        cursor = mysql.connection.cursor()
        cursor.execute(f"SELECT * FROM {table_name} WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            if role=='Customer':
                return render_template('customer_dashboard.html', user=user)
            elif role=='Admin':
                return render_template('admin_dashboard.html',user=user)
            else :
                return render_template('merchant_dashboard.html',user=user)
    return redirect(url_for('login'))

@app.route('/customer_gift_cards')
def customer_gift_cards():
    if 'user_id' in session:
        user_id = session['user_id']
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT card_name, card_value FROM gift_cards WHERE customer_id = %s", (user_id,))
        gift_cards = cursor.fetchall()
        cursor.close()

        return render_template('customer_gift_cards.html', gift_cards=gift_cards)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

@app.route('/add_gift_card', methods=['GET', 'POST'])
def add_gift_card():
    form = GiftCardForm()
    merchant_id = session.get('user_id')

    if form.validate_on_submit():
        card_name = form.card_name.data
        card_value = form.card_value.data
        issue_date = form.issue_date.data
        expiry_date = form.expiry_date.data

        cursor = mysql.connection.cursor()
        query = """
            INSERT INTO gift_cards (card_name, card_value, issue_date, expiry_date, merchant_id, available)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (card_name, card_value, issue_date, expiry_date, merchant_id, True))
        mysql.connection.commit()
        cursor.close()

        flash('Gift card added successfully!', 'success')
        return redirect(url_for('merchant_gift_cards'))

    return render_template('add_gift_card.html', form=form)

@app.route('/merchant_gift_cards')
def merchant_gift_cards():
    merchant_id = session.get('user_id')
    cursor = mysql.connection.cursor()
    query = """
        SELECT card_id, card_name, card_value, issue_date, expiry_date
        FROM gift_cards
        WHERE merchant_id = %s
    """
    cursor.execute(query, (merchant_id,))
    gift_cards = cursor.fetchall()
    cursor.close()

    form = FlaskForm()
    return render_template('merchant_gift_cards.html', gift_cards=gift_cards, form=form)

@app.route('/update_gift_card/<int:card_id>', methods=['GET', 'POST'])
def update_gift_card(card_id):
    form = GiftCardForm()
    merchant_id = session.get('user_id')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM gift_cards WHERE card_id = %s AND merchant_id = %s", (card_id, merchant_id))
    card_data = cursor.fetchone()
    cursor.close()

    if not card_data:
        flash('Gift card not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('merchant_gift_cards'))

    if request.method == 'GET':
        form.card_name.data = card_data[1]
        form.card_value.data = card_data[2]
        form.issue_date.data = card_data[3]
        form.expiry_date.data = card_data[4]

    if form.validate_on_submit():
        card_name = form.card_name.data
        card_value = form.card_value.data
        issue_date = form.issue_date.data
        expiry_date = form.expiry_date.data

        cursor = mysql.connection.cursor()
        query = """
            UPDATE gift_cards
            SET card_name = %s, card_value = %s, issue_date = %s, expiry_date = %s
            WHERE card_id = %s AND merchant_id = %s
        """
        cursor.execute(query, (card_name, card_value, issue_date, expiry_date, card_id, merchant_id))
        mysql.connection.commit()
        cursor.close()

        flash('Gift card updated successfully!', 'success')
        return redirect(url_for('merchant_gift_cards'))

    return render_template('update_gift_card.html', form=form)

@app.route('/delete_gift_card/<int:card_id>', methods=['POST'])
def delete_gift_card(card_id):
    form = FlaskForm()

    if form.validate_on_submit():
        merchant_id = session.get('user_id')

        cursor = mysql.connection.cursor()
        query = "DELETE FROM gift_cards WHERE card_id = %s AND merchant_id = %s"
        cursor.execute(query, (card_id, merchant_id))
        mysql.connection.commit()
        cursor.close()

        flash('Gift card deleted successfully!', 'success')
    else:
        flash('Failed to delete the gift card due to missing or invalid CSRF token.', 'danger')

    return redirect(url_for('merchant_gift_cards'))

@app.route('/gift_cards', methods=['GET', 'POST'])
def gift_cards():
    form = FlaskForm()
    search_query = request.args.get('search')
    
    cursor = mysql.connection.cursor()
    if search_query:
        cursor.execute("SELECT card_id, card_name, card_value FROM gift_cards WHERE available=True AND card_name LIKE %s", ('%' + search_query + '%',))
    else:
        cursor.execute("SELECT card_id, card_name, card_value FROM gift_cards WHERE available=True")
    
    gift_cards = cursor.fetchall()
    cursor.close()
    
    return render_template('gift_cards.html', gift_cards=gift_cards, form=form)


@app.route('/request_gift_card', methods=['GET', 'POST'])
def request_gift_card():
    form = GiftCardRequestForm()
    if form.validate_on_submit():
        card_name = form.card_name.data
        card_value = form.card_value.data
        quantity = form.quantity.data
        customer_id = session.get('user_id')
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT card_id FROM gift_cards WHERE card_name = %s AND card_value = %s", (card_name, card_value))
        result = cursor.fetchone()
        if result:
            card_id = result[0]
            
            cursor.execute("""
                INSERT INTO gift_card_requests (customer_id, card_name, card_value, card_id, quantity)
                VALUES (%s, %s, %s, %s, %s)
            """, (customer_id, card_name, card_value, card_id, quantity))
            mysql.connection.commit()
            cursor.close()
            
            flash("Your request for the gift card has been submitted!", 'success')
            return redirect(url_for('gift_cards'))
        else:
            flash("Card not found", 'danger')
    return render_template('request_gift_card.html', form=form)

@app.route('/merchant_requests')
def merchant_requests():
    merchant_id = session.get('user_id')

    cursor = mysql.connection.cursor()
    query = """
        SELECT r.request_id, c.name AS customer_name, g.card_name, r.quantity, r.status
        FROM gift_card_requests r
        JOIN gift_cards g ON r.card_id = g.card_id
        JOIN users c ON r.customer_id = c.id
        WHERE g.merchant_id = %s
    """
    cursor.execute(query, (merchant_id,))
    requests = cursor.fetchall()
    cursor.close()

    return render_template('merchant_requests.html', requests=requests)

@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
    cursor = mysql.connection.cursor()
    
    cursor.execute("SELECT customer_id, card_id, quantity FROM gift_card_requests WHERE request_id = %s", (request_id,))
    request = cursor.fetchone()
    
    if request:
        customer_id, card_id, quantity = request
        
        for _ in range(quantity):
            cursor.execute("""
                INSERT INTO customer_gift_cards (customer_id, card_id)
                VALUES (%s, %s)
            """, (customer_id, card_id))
        
        cursor.execute("UPDATE gift_card_requests SET status = 'Approved' WHERE request_id = %s", (request_id,))
        mysql.connection.commit()
    
    cursor.close()
    flash("Request approved successfully!", 'success')
    return redirect(url_for('merchant_requests'))

@app.route('/deny_request/<int:request_id>')
def deny_request(request_id):
    cursor = mysql.connection.cursor()
    
    cursor.execute("SELECT customer_id FROM gift_card_requests WHERE request_id = %s", (request_id,))
    request = cursor.fetchone()
    
    if request:
        customer_id = request[0]
        
        cursor.execute("UPDATE gift_card_requests SET status = 'Denied' WHERE request_id = %s", (request_id,))
        mysql.connection.commit()
    
    cursor.close()
    flash("Request denied successfully!", 'success')
    return redirect(url_for('merchant_requests'))


@app.route('/buy_gift_card', methods=['GET', 'POST'])
def buy_gift_card():
    form = BuyGiftCardForm()
    search_query = request.args.get('search')
    cursor = mysql.connection.cursor()
    
    if search_query:
        cursor.execute("SELECT card_id, card_name FROM gift_cards WHERE available=True AND card_name LIKE %s", ('%' + search_query + '%',))
    else:
        cursor.execute("SELECT card_id, card_name FROM gift_cards WHERE available=True")
    
    gift_cards = cursor.fetchall()
    form.card_name.choices = [(card[0], card[1]) for card in gift_cards]
    cursor.close()

    if form.validate_on_submit():
        card_id = form.card_name.data
        quantity = form.quantity.data
        user_id = session.get('user_id')
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT card_value, merchant_id FROM gift_cards WHERE card_id=%s AND available=True", (card_id,))
        card = cursor.fetchone()
        
        print("Card data from database:", card)  # Add this line for debugging
        
        if card:
            card_value, merchant_id = card
            try:
                card_value = int(card_value)  # Convert card_value to integer
            except ValueError:
                print("Error: Could not convert card_value to integer")
                return redirect(url_for('buy_gift_card'))
                
            total_cost = card_value * quantity

            cursor.execute("SELECT balance FROM users WHERE id=%s", (user_id,))
            user = cursor.fetchone()
            if user and int(user['balance']) >= total_cost:
                new_balance = int(user['balance']) - total_cost
                cursor.execute("UPDATE users SET balance=%s WHERE id=%s", (new_balance, user_id))

                cursor.execute("SELECT balance FROM merchant WHERE id=%s", (merchant_id,))
                merchant = cursor.fetchone()
                if merchant:
                    new_merchant_balance = merchant['balance'] + total_cost
                    cursor.execute("UPDATE merchant SET balance=%s WHERE id=%s", (new_merchant_balance, merchant_id))

                for _ in range(quantity):
                    cursor.execute("UPDATE gift_cards SET available=False WHERE card_id=%s", (card_id,))
                    
                    transaction_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute("""
                        INSERT INTO transaction (transaction_date, transaction_amount, card_id)
                        VALUES (%s, %s, %s)
                    """, (transaction_date, total_cost, card_id))

                mysql.connection.commit()
                cursor.close()
                
                flash(f"You have successfully bought {quantity} {card_id} gift card(s)!")
                return redirect(url_for('buy_gift_card'))
            else:
                flash("Insufficient balance to purchase the gift card(s)!")
        else:
            flash("Selected gift card is not available!")
    return render_template('buy_gift_card.html', form=form, search_query=search_query)




@app.route('/merchant_transactions')
def merchant_transactions():
    merchant_id = session.get('user_id')

    cursor = mysql.connection.cursor()
    query = """
        SELECT t.transaction_id, t.transaction_date, CAST(t.transaction_amount AS DECIMAL(10,2)), g.card_name
        FROM transaction t
        JOIN gift_cards g ON t.card_id = g.card_id
        WHERE g.merchant_id = %s
        ORDER BY t.transaction_date DESC
    """
    cursor.execute(query, (merchant_id,))
    transactions = cursor.fetchall()
    cursor.close()

    return render_template('merchant_transactions.html', transactions=transactions)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session and session['role'] == 'Admin':
        return render_template('admin_dashboard.html')
    else:
        return redirect(url_for('login'))

@app.route('/admin/users')
def admin_users():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/merchants')
def admin_merchants():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM merchant")
    merchants = cursor.fetchall()
    cursor.close()
    return render_template('admin_merchants.html', merchants=merchants)

@app.route('/admin/gift_cards')
def admin_gift_cards():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM gift_cards")
    gift_cards = cursor.fetchall()
    cursor.close()
    return render_template('admin_gift_cards.html', gift_cards=gift_cards)

@app.route('/admin/transactions')
def admin_transactions():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM transaction")
    transactions = cursor.fetchall()
    cursor.close()
    return render_template('admin_transactions.html', transactions=transactions)

@app.route('/admin/create_user', methods=['GET', 'POST'])
def admin_create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        
        cursor = mysql.connection.cursor()
        query = f"INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (name, email, hashed_password, role))
        mysql.connection.commit()
        cursor.close()

        flash("User created successfully!")
        return redirect(url_for('admin_users'))

    return render_template('admin_create_user.html', form=form)

@app.route('/admin/update_user/<int:user_id>', methods=['GET', 'POST'])
def admin_update_user(user_id):
    form = UpdateUserForm()
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'GET':
        form.name.data = user['name']
        form.email.data = user['email']
        form.balance.data = user['balance']

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        balance = form.balance.data
        print("Balancd : ",balance)
        cursor = mysql.connection.cursor()
        query = "UPDATE users SET name=%s, email=%s, balance=%s WHERE id=%s"
        cursor.execute(query, (name, email, balance, user_id))
        mysql.connection.commit()
        cursor.close()

        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin_update_user.html', form=form)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    form = FlaskForm()

    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        mysql.connection.commit()
        cursor.close()

        flash('User deleted successfully!', 'success')
    else:
        flash('Failed to delete the user due to missing or invalid CSRF token.', 'danger')

    return redirect(url_for('admin_users'))

@app.route('/admin/create_merchant', methods=['GET', 'POST'])
def admin_create_merchant():
    form = CreateUserForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        
        cursor = mysql.connection.cursor()
        query = f"INSERT INTO merchant (name, email, password, role) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (name, email, hashed_password, role))
        mysql.connection.commit()
        cursor.close()

        flash("Merchant created successfully!")
        return redirect(url_for('admin_merchants'))

    return render_template('admin_create_merchant.html', form=form)

@app.route('/admin/update_merchant/<int:merchant_id>', methods=['GET', 'POST'])
def admin_update_merchant(merchant_id):
    form = UpdateUserForm()
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM merchant WHERE id = %s", (merchant_id,))
    merchant = cursor.fetchone()
    cursor.close()

    if not merchant:
        flash('Merchant not found.', 'danger')
        return redirect(url_for('admin_merchants'))

    if request.method == 'GET':
        form.name.data = merchant['name']
        form.email.data = merchant['email']
        form.balance.data = merchant['balance']

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        balance = form.balance.data

        cursor = mysql.connection.cursor()
        query = "UPDATE merchant SET name=%s, email=%s, balance=%s WHERE id=%s"
        cursor.execute(query, (name, email, balance, merchant_id))
        mysql.connection.commit()
        cursor.close()

        flash('Merchant updated successfully!', 'success')
        return redirect(url_for('admin_merchants'))

    return render_template('admin_update_merchant.html', form=form)

@app.route('/admin/delete_merchant/<int:merchant_id>', methods=['POST'])
def admin_delete_merchant(merchant_id):
    form = FlaskForm()

    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        query = "DELETE FROM merchant WHERE id = %s"
        cursor.execute(query, (merchant_id,))
        mysql.connection.commit()
        cursor.close()

        flash('Merchant deleted successfully!', 'success')
    else:
        flash('Failed to delete the merchant due to missing or invalid CSRF token.', 'danger')

    return redirect(url_for('admin_merchants'))

if __name__ == '__main__':
    app.run(debug=True)
