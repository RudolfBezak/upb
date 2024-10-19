import datetime
from flask import Flask, flash, render_template, redirect, request, url_for
from flask_wtf import FlaskForm
import nacl
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import nacl.pwhash

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_TIME = 15  # in minutes

def load_common_passwords(filename='./z3/commonPasswords.txt'):
    try:
        with open(filename, 'r') as file:
            return {line.strip() for line in file if line.strip()}
    except Exception as e:
        print(f"Error loading common passwords: {e}")
        return set()

# Global variable to hold common passwords
common_passwords = load_common_passwords()

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela

    TODO: tabulku je treba doimplementovat
'''
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=False, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
with app.app_context():
    # Create all tables if they don't exist
    db.create_all()

    # Check if the test user already exists
    test_user = User.query.filter_by(username='test').first()
    if not test_user:
        # Only add the user if they don't exist
        test_user = User(username='test', password='test')  # Make sure to hash the password
        db.session.add(test_user)
        db.session.commit()
        print("Test user created.")
    else:
        print("Test user already exists.")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired()])
    submit = SubmitField('Register')

login_attempts = {}

def hash_password(password):
    # Using argon2 password hashing
    return nacl.pwhash.str(password.encode('utf-8'))

def register_user(username, password):
    hashed_password = hash_password(password)
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()


@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # Get the user's IP address
    user_ip = request.remote_addr

    # Initialize attempts for this IP if not already done
    if user_ip not in login_attempts:
        login_attempts[user_ip] = {'count': 0, 'first_attempt': None}

    # Check if the user is currently blocked
    if login_attempts[user_ip]['count'] >= MAX_LOGIN_ATTEMPTS:
        first_attempt_time = login_attempts[user_ip]['first_attempt']
        if first_attempt_time and datetime.datetime.now() - first_attempt_time < datetime.timedelta(minutes=LOGIN_BLOCK_TIME):
            flash('Too many login attempts. Please try again later.', 'danger')
            return render_template('login.html', form=form)
        else:
            # Reset the attempts if the block time has passed
            login_attempts[user_ip] = {'count': 0, 'first_attempt': None}

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Query for the user by username
        user = User.query.filter_by(username=username).first()

        if user:
            try:
                # Verify password using PyNaCl
                if nacl.pwhash.verify(user.password, password.encode('utf-8')):
                    login_user(user)
                    # Reset the login attempts upon successful login
                    login_attempts[user_ip]['count'] = 0
                    login_attempts[user_ip]['first_attempt'] = None
                    return redirect(url_for('home'))
                else:
                    flash('Invalid username or password', 'danger')
            except nacl.exceptions.InvalidkeyError:
                flash('Invalid password', 'danger')
        else:
            flash('User not found', 'danger')

        # Increment the login attempt count if login fails
        login_attempts[user_ip]['count'] += 1
        if login_attempts[user_ip]['first_attempt'] is None:
            login_attempts[user_ip]['first_attempt'] = datetime.datetime.now()

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])  
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        passwordCheck = form.confirm_password.data

        if (password != passwordCheck):
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', form=form)
        
        print(password in common_passwords)
        print(common_passwords)

        if password in common_passwords:
            flash('Your password is too common. Please choose a different one.', 'danger')
            return render_template('register.html', form=form)

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists, please choose a different one.', 'danger')
            return render_template('register.html', form=form)
        
        # Password requirements
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html', form=form)
        
        if not any(char.isdigit() for char in password):
            flash('Password must contain at least one digit.', 'danger')
            return render_template('register.html', form=form)
        
        if not any(char.isupper() for char in password):
            flash('Password must contain at least one uppercase letter.', 'danger')
            return render_template('register.html', form=form)
        
        if not any(char.islower() for char in password):
            flash('Password must contain at least one lowercase letter.', 'danger')
            return render_template('register.html', form=form)
        
        if not any(char in '!@#$%^&*()-_=+[]{}|;:,.<>?/~`' for char in password):
            flash('Password must contain at least one special character.', 'danger')
            return render_template('register.html', form=form)
        
        if not all(char.isalnum() or char in '!@#$%^&*()-_=+[]{}|;:,.<>?/~`' for char in password):
            flash('Password must only contain alphanumeric characters and special characters.', 'danger')
            return render_template('register.html', form=form)

        # Hash the password using PyNaCl
        hashed_password = hash_password(password)

        # Create new user with hashed password
        new_user = User(username=username, password=hashed_password)
        
        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=1337)