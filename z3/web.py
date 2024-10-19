from flask import Flask, flash, render_template, redirect, url_for
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
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

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

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Query for the user by username
        user = User.query.filter_by(username=username).first()

        if user:
            try:
                # Verify password using argon2
                if nacl.pwhash.verify(user.password, password.encode('utf-8')):
                    login_user(user)
                    return redirect(url_for('home'))
                else:
                    flash('Invalid username or password', 'danger')
            except nacl.exceptions.InvalidkeyError:
                flash('Invalid password', 'danger')
        else:
            flash('User not found', 'danger')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])  
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists, please choose a different one.', 'danger')
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