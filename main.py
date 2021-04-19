import os
import random
from datetime import datetime

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
from data.messages import Messages
from data import db_session
from forms.AboutMeForm import AboutMeForm
from forms.ChangeCountryForm import ChangeCountryForm
from forms.ChangeDateOfBirthdayForm import ChangeDateOfBirthdayForm
from forms.ChangePasswordForm import ChangePasswordForm
from forms.ChangePasswordOldPasswordForm import ChangePasswordOldPasswordForm
from forms.ChangeUsernameForm import ChangeUsernameForm
from forms.EditProfileForm import EditProfileForm
from forms.ForgotForm import ForgotForm
from forms.MessageForm import MessageForm
from forms.LoginForm import LoginForm
from forms.RegisterForm import RegisterForm
from forms.Register2Form import Register2Form
from forms.RestrictAccessForm import RestrictAccessForm
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


def main():
    db_session.global_init("db/twitter2.db")
    app.run(host='127.0.0.1', port=8080)


@app.route('/')
@app.route('/index')
def welcome_page():
    db_sess = db_session.create_session()
    return render_template('welcome.html', title='Добро пожаловать', bg_text='')


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
        try:
            db_sess = db_session.create_session()
            user = db_sess.query(User).filter(User.email == form.login.data or
                                              User.username == form.login.data).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember_me.data)
                return redirect('/account/' + current_user.username)
        except Exception:
            return render_template('login.html',
                                   message="Такого пользоватея не существует",
                                   form=form, bg_size=200)
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
        return redirect('/account/' + user.username)
    return render_template('aboutme.html', title='Register Form', form=form)


@app.route('/editprofile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if request.method == "GET":
        form.username.data = current_user.username
        form.about.data = current_user.about_me
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.username == form.username.data).first()
        if user and user != current_user:
            return render_template('editprofile.html', title='EditProfile',
                                   form=form, css_file=url_for('static', filename='css/style.css'),
                                   message="This name is already exists"
                                   )

        current_user.username = form.username.data
        current_user.about_me = form.about.data

        db_sess.merge(current_user)
        db_sess.commit()
        return redirect('/account/' + current_user.username)
    return render_template('editprofile.html', title='Edit Profile', userlist=get_userlist(),
                           form=form, css_file=url_for('static', filename='css/style.css'))


@app.route('/account/<username>', methods=['GET', 'POST'])
@login_required
def account(username):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.username == username).first()
    if not user:
        abort(404)
    return render_template('account.html', title='', user=user, url_for=url_for,
                           userimg=url_for('static', filename='img/' + user.photo),
                           css_file=url_for('static', filename='css/style.css'),
                           userlist=get_userlist(),
                           str=str)


@app.route('/subscribe/<username>', methods=['GET', 'POST'])
@login_required
def subscribe(username):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.username == username).first()
    current_user.following = ', '.join(current_user.following.split(', ') + [str(user.id)])
    user.followers = ', '.join(user.following.split(', ') + [str(current_user.id)])
    db_sess.merge(current_user)
    db_sess.merge(user)
    db_sess.commit()
    return redirect(f'/account/{user.username}')


@app.route('/unsubscribe/<username>', methods=['GET', 'POST'])
@login_required
def unsubscribe(username):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.username == username).first()
    following_list = current_user.following.split(', ')
    following_list.remove(str(user.id))
    current_user.following = ', '.join(following_list)
    followers_list = user.followers.split(', ')
    followers_list.remove(str(current_user.id))
    user.followers = ', '.join(followers_list)
    db_sess.merge(current_user)
    db_sess.merge(user)
    db_sess.commit()
    return redirect(f'/account/{user.username}')


@app.route('/following/<username>', methods=['GET', 'POST'])
@login_required
def following(username):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.username == username).first()
    if not user:
        abort(404)
    return render_template('following.html', title='', user=user,
                           url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           str=str, db_sess_query_user=db_sess.query(User), user_class=User)


@app.route('/followers/<username>', methods=['GET', 'POST'])
@login_required
def followers(username):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.username == username).first()
    if not user:
        abort(404)
    return render_template('followers.html', title='', user=user,
                           url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           str=str, db_sess_query_user=db_sess.query(User), user_class=User)


@app.route('/account_settings/<username>', methods=['GET', 'POST'])
@login_required
def account_settings(username):
    return render_template('accountsettings.html', title='', user=current_user,
                           url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


@app.route('/delete_account/<username>', methods=['GET', 'POST'])
@login_required
def delete_account(username):
    db_sess = db_session.create_session()
    return render_template('deleteaccount.html', title='', user=current_user,
                           url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


@app.route('/delete/<username>', methods=['GET', 'POST'])
@login_required
def delete(username):
    db_sess = db_session.create_session()

    for id in current_user.following.split(', '):
        user = db_sess.query(User).filter(User.id == id).first()
        if user:
            followers_list = user.followers.split(', ')
            followers_list.remove(str(current_user.id))
            user.followers = ', '.join(followers_list)
            db_sess.merge(user)

    for id in current_user.followers.split(', '):
        user = db_sess.query(User).filter(User.id == id).first()
        if user:
            following_list = user.following.split(', ')
            following_list.remove(str(current_user.id))
            user.following = ', '.join(following_list)
            db_sess.merge(user)

    db_sess.delete(current_user)
    db_sess.commit()
    return redirect('/')


@app.route('/privacy_and_security/<username>', methods=['GET', 'POST'])
@login_required
def privacy_and_security(username):
    return render_template('privacyandsecurity.html', title='', user=current_user,
                           url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Privacy and security'
                           )


@app.route('/change_old_password', methods=['GET', 'POST'])
@login_required
def change_old_password():
    db_sess = db_session.create_session()

    form = ChangePasswordOldPasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.password.data):
            return render_template('changepasswordnotforgot.html', title='Change Password',
                                   form=form, user=current_user, userlist=get_userlist(),
                                   message="Incorrect password",
                                   params='Account settings', css_file=url_for('static', filename='css/style.css'),
                                   )
        return redirect('/new_password')

    return render_template('changepasswordnotforgot.html', title='Change Password',
                           user=current_user, url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings', form=form
                           )


@app.route('/new_password', methods=['GET', 'POST'])
@login_required
def new_password():
    db_sess = db_session.create_session()

    form = ChangePasswordForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('newpassword.html', title='Change password',
                                   userlist=get_userlist(),
                                   form=form, user=current_user, css_file=url_for('static', filename='css/style.css'),
                                   message="Password mismatch",
                                   params='Account settings'
                                   )
        db_sess = db_session.create_session()
        current_user.set_password(form.password.data)
        db_sess.merge(current_user)
        db_sess.commit()
        return render_template('newpassword.html', title='Change Password',
                               userlist=get_userlist(),
                               form=form, user=current_user, css_file=url_for('static', filename='css/style.css'),
                               message="The password was changed successfully",
                               params='Account settings'
                               )

    return render_template('newpassword.html', title='', user=current_user,
                           url_for=url_for, form=form, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


def get_userlist():
    return sorted(db_session.create_session().query(User).filter(User.username != current_user.username),
                  key=lambda x: [0 if str(x.id) in current_user.following.split(', ') else 1,
                                 - len(list(set(current_user.following.split(', ')) & set(
                                     x.following.split(', ')))),
                                 - len(list(set(current_user.followers.split(', ')) & set(
                                     x.followers.split(', ')))),
                                 x.username])


@app.route('/account_information/<username>', methods=['GET', 'POST'])
@login_required
def account_information(username):
    return render_template('accountinformation.html', title='',
                           url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


@login_required
def account_information(username):
    return render_template('accountinformation.html', title='',
                           url_for=url_for, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


@app.route('/change_username', methods=['GET', 'POST'])
@login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.username == form.username.data).first():
            return render_template('changeusername.html', title='Change Username',
                                   userlist=get_userlist(),
                                   form=form, css_file=url_for('static', filename='css/style.css'),
                                   message="This name is already exists",
                                   params='Account settings'
                                   )
        else:
            current_user.username = form.username.data
            db_sess.merge(current_user)
            db_sess.commit()
            return render_template('changeusername.html', title='Change Username',
                                   userlist=get_userlist(),
                                   form=form, css_file=url_for('static', filename='css/style.css'),
                                   message="The username was changed successfully",
                                   params='Account settings'
                                   )

    return render_template('changeusername.html', title='Change Username',
                           url_for=url_for, form=form, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


@app.route('/change_date_of_birthday', methods=['GET', 'POST'])
@login_required
def change_date_of_birthday():
    form = ChangeDateOfBirthdayForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        current_user.year_of_birth = form.year.data
        current_user.month_of_birth = form.month.data
        current_user.day_of_birth = form.day.data
        db_sess.merge(current_user)
        db_sess.commit()
        return render_template('changedateofbirthday.html', title='Change date of birthday',
                               form=form, css_file=url_for('static', filename='css/style.css'),
                               message="The date of birthday was changed successfully",
                               params='Account settings', userlist=get_userlist()
                               )

    return render_template('changedateofbirthday.html', title='Change date of birthday',
                           url_for=url_for, form=form, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


@app.route('/change_country', methods=['GET', 'POST'])
@login_required
def change_country():
    form = ChangeCountryForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        current_user.country = form.country.data
        db_sess.merge(current_user)
        db_sess.commit()
        return render_template('changecountry.html', title='Change Country',
                               userlist=get_userlist(),
                               form=form, css_file=url_for('static', filename='css/style.css'),
                               message="The country was changed successfully",
                               params='Account settings'
                               )

    return render_template('changecountry.html', title='Change Country',
                           url_for=url_for, form=form, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Account settings'
                           )


@app.route('/restrict_access', methods=['GET', 'POST'])
@login_required
def restrict_access():
    form = RestrictAccessForm()
    if request.method == 'POST' and form.validate():
        db_sess = db_session.create_session()
        current_user.restrict = form.restrict.data
        db_sess.merge(current_user)
        db_sess.commit()
        return render_template('restrictaccess.html', title='Restrict',
                               userlist=get_userlist(),
                               form=form, css_file=url_for('static', filename='css/style.css'),
                               message="Access is open" if not current_user.restrict else "Access limited",
                               params='Privacy and security'
                               )

    return render_template('restrictaccess.html', title='Restrict',
                           url_for=url_for, form=form, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Privacy and security'
                           )


@app.route('/blacklist', methods=['GET', 'POST'])
@login_required
def blacklist():
    db_sess = db_session.create_session()
    return render_template('blacklist.html', title='Blacklist',
                           url_for=url_for, user_class=User, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           params='Privacy and security', str=str, db_sess_query_user=db_sess.query(User)
                           )


@app.route('/delete_from_blacklist/<username>', methods=['GET', 'POST'])
@login_required
def delete_from_blacklist(username):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.username == username).first()
    blacklist = current_user.blacklist.split(', ')
    blacklist.remove(str(user.id))
    current_user.blacklist = ', '.join(blacklist)
    db_sess.merge(current_user)
    db_sess.commit()
    return redirect(f'/blacklist')


@app.route('/add_to_blacklist/<username>', methods=['GET', 'POST'])
@login_required
def add_to_blacklist(username):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.username == username).first()
    current_user.blacklist = ', '.join(current_user.blacklist.split(', ') + [str(user.id)])
    db_sess.merge(current_user)
    db_sess.commit()
    if not str(user.id) in current_user.following.split(', '):
        return redirect(f'/account/{user.username}')
    return redirect(f'/unsubscribe/{user.username}')


@app.route('/messenger/<username>', methods=['GET', 'POST'])
@login_required
def messenger(username):
    db_sess = db_session.create_session()
    form = MessageForm()
    user = db_sess.query(User).filter(User.username == username).first()

    if form.validate_on_submit():
        add_message(current_user.id, user.id, form.message.data)
        return redirect(f'/messenger/{username}')

    return render_template('messenger.html', title='Messenger', form=form, user=user,
                           url_for=url_for, user_class=User, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           messages_list=db_sess.query(Messages).filter(((Messages.from_id == current_user.id) / (Messages.to_id == user.id)) |
                                                                        ((Messages.to_id == current_user.id) / (Messages.from_id == user.id))).all(),
                           str=str, db_sess_query_user=db_sess.query(User)
                           )


def add_message(from_id, to_id, message_text):
    db_sess = db_session.create_session()
    message = Messages(
        from_id=from_id,
        to_id=to_id,
        message_text=message_text,
    )
    db_sess.add(message)
    db_sess.commit()


@app.route('/delete_message/<message_id>', methods=['GET', 'POST'])
@login_required
def delete_message(message_id):
    db_sess = db_session.create_session()
    message = db_sess.query(Messages).filter(Messages.id == int(message_id)).first()
    user = db_sess.query(User).filter(User.id == message.to_id).first()
    db_sess.delete(message)
    db_sess.commit()
    return redirect(f'/messenger/{user.username}')


@app.route('/chats', methods=['GET', 'POST'])
@login_required
def chats():
    db_sess = db_session.create_session()
    interlocutor_id = db_sess.query(Messages).filter((Messages.from_id == current_user.id) | (Messages.to_id == current_user.id))
    interlocutor_users = [db_sess.query(User).filter(User.id == message.from_id).first() for message in interlocutor_id] +\
                         [db_sess.query(User).filter(User.id == message.to_id).first() for message in interlocutor_id]
    interlocutor_users = [user for user in interlocutor_users if user.id != current_user.id]
    i = 0
    while len(interlocutor_users) != len(set(interlocutor_users)):
        if interlocutor_users.index(interlocutor_users[i]) != i:
            interlocutor_users.remove(interlocutor_users[i])
        else:
            i += 1
    interlocutor_users.sort(key=lambda x: list(map(lambda x: x.from_id if x.from_id != current_user.id else x.to_id, interlocutor_id))[::-1].index(x.id))
    interlocutor_last_messages = []
    for user in interlocutor_users:
        messages = db_sess.query(Messages).filter(((Messages.from_id == user.id) / (Messages.to_id == current_user.id)) |
                                                                         ((Messages.to_id == user.id) / (Messages.from_id == current_user.id))).all()
        if messages:
            interlocutor_last_messages.append(messages[::-1][0])
    return render_template('chats.html', title='Messenger',
                           url_for=url_for, user_class=User, userlist=get_userlist(),
                           css_file=url_for('static', filename='css/style.css'),
                           chat_list=interlocutor_users, interlocutor_last_messages=interlocutor_last_messages,
                           str=str, db_sess_query_user=db_sess.query(User), datetime=datetime
                           )


if __name__ == '__main__':
    main()
