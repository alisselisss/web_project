import os
import random

from flask_migrate import Migrate
from flask_script import Manager
from flask import Flask, render_template, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.datastructures import CombinedMultiDict
from werkzeug.exceptions import abort
from werkzeug.utils import redirect, secure_filename
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate, MigrateCommand

from data.users import User
from data import db_session
from forms.AboutMeForm import AboutMeForm
from forms.ChangePasswordForm import ChangePasswordForm
from forms.ForgotForm import ForgotForm
from forms.LoginForm import LoginForm
from forms.RegisterForm import RegisterForm
from forms.Register2Form import Register2Form
from forms.UploadPhotoForm import UploadPhotoForm
from forms.VerificationForm import VerificationForm

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////db/twitter2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'webproject0909@gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'webproject0909@gmail.com'
app.config['MAIL_PASSWORD'] = 'qqqppp123456789'

manager = Manager(app)
manager.add_command('db', MigrateCommand)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)


@app.route('/')
@app.route('/index')
def welcome_page():
    db_sess = db_session.create_session()
    return render_template('welcome.html', title='титле....')


def main():
    db_session.global_init("db/twitter2.db")
    app.run(host='127.0.0.1', port=8000)


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.login.data or
                                          User.username == form.login.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect('/account')
        return render_template('login.html',
                               message="Incorrect login or password",
                               form=form)
    return render_template('login.html', title='Authorization', form=form,
                           css_file=url_for('static', filename='css/style.css'))


@app.route('/send_verification')
def send_verification():
    global verification_code, user
    verification_code = random.randint(100000, 1000000)
    msg = Message("подтверждение почты", recipients=[user.email])
    msg.body = f"провер очка адреса элпочты\nлалала вам пришел код подтверждения {verification_code}\nесли вы не отправляли данный запрос то проигнорьте эту смсочку\nс уважением техподдержка twitter2"
    mail.send(msg)
    print(verification_code)
    return redirect('/verification')


@app.route('/password_reset', methods=['GET', 'POST'])
def forgot_password():
    global user, back
    form = ForgotForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.login.data or
                                          User.username == form.login.data).first()
        if user:
            back = '/password_reset'
            return redirect("/itsme")
    return render_template('forgot.html', title='Sign up', form=form)


@app.route('/itsme', methods=['GET', 'POST'])
def itsme():
    global user
    return render_template('itsme.html', title='Sign up', user=user,
                           userimg=url_for('static', filename='img/' + user.photo),
                           css_file=url_for('static', filename='css/style.css')
                           )


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    global user, back
    form = RegisterForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Sign up',
                                   form=form,
                                   message="This email is already exists")
        if db_sess.query(User).filter(User.username == form.username.data).first():
            return render_template('register.html', title='Sign up',
                                   form=form,
                                   message="This name is already exists")

        user = User(
            username=form.username.data,
            email=form.email.data,
            month_of_birth=form.month.data,
            day_of_birth=form.day.data,
            year_of_birth=form.year.data,
            country=form.country.data
        )
        back = '/register'
        return redirect('/send_verification')
    return render_template('register.html', title='Sign up', form=form)


@app.route('/verification', methods=['GET', 'POST'])
def verification():
    global verification_code, back
    form = VerificationForm()
    if form.validate_on_submit():
        if form.verification.data != verification_code:
            return render_template('verification.html', title='Sign up',
                                   form=form,
                                   message="Invalid verification code")
        return redirect('/register2') if back == '/register' else redirect('/сhange_password')
    return render_template('verification.html', title='Sign up', form=form, back=back)


@app.route('/сhange_password', methods=['GET', 'POST'])
def сhange_password():
    global user
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('changepassword.html', title='Sign up',
                                   form=form,
                                   message="Password mismatch")
        db_sess = db_session.create_session()
        user.set_password(form.password.data)
        db_sess.merge(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('changepassword.html', title='Sign up', form=form, back=back)


@app.route('/register2', methods=['GET', 'POST'])
def reqister2():
    global user
    form = Register2Form()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register2.html', title='Sign up',
                                   form=form,
                                   message="Password mismatch")
        user.set_password(form.password.data)
        return redirect('/upload_photo')
    return render_template('register2.html', title='Register Form', form=form)


@app.route('/upload_photo', methods=['GET', 'POST'])
def upload_photo():
    global user
    form = UploadPhotoForm(CombinedMultiDict((request.files, request.form)))
    if form.validate_on_submit():
        f = form.upload.data
        filename = secure_filename(f.filename)
        f.save(os.path.join('static\img', filename))
        user.photo = filename if filename else 'no_photo.jpg'
        return redirect('/aboutme')

    return render_template('uploadphoto.html', form=form)


@app.route('/aboutme', methods=['GET', 'POST'])
def about_me():
    global user
    form = AboutMeForm()
    if form.validate_on_submit():
        user.about_me = form.about.data
        db_sess = db_session.create_session()
        db_sess.add(user)
        db_sess.commit()
        return redirect('/account')
    return render_template('aboutme.html', title='Register Form', form=form)


@app.route('/account', methods=['GET', 'POST'])
def account():
    return render_template('account.html', title='')


if __name__ == '__main__':
    main()
