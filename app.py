from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\abdel\\Documents\\loginexample\\database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class MeetingGuests(db.Model):
    __tablename__ = 'meeting_guests'
    guest_id = db.Column(db.Integer, db.ForeignKey('user.id'),primary_key=True)
    meeting_id = db.Column(db.Integer, db.ForeignKey('meeting.id'),primary_key=True)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    usertype = db.Column(db.String(15))
    meetings = db.relationship('Meeting', backref='moderator')
    rooms = db.relationship('Meeting', secondary="meeting_guests")



class Meeting(db.Model):
    __tablename__ = 'meeting'
    id = db.Column(db.Integer, primary_key=True)
    meetingname = db.Column(db.String(25), unique=True)
    password = db.Column(db.String(80))
    active= db.Column(db.String(15))
    moderator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    guests = db.relationship("User", secondary="meeting_guests")
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


class CreateMeetingForm(FlaskForm):
    meetingname = StringField('meeting name', validators=[InputRequired(), Length(min=4, max=15)])
    meetingpassword = PasswordField('meeting password', validators=[InputRequired(), Length(min=8, max=80)])

class UserForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,usertype ='user')
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/new-meeting', methods=['GET', 'POST'])
@login_required
def new_meeting():
    
    form = CreateMeetingForm()
    if form.validate_on_submit():
        new_meeting = Meeting(meetingname=form.meetingname.data, password=form.meetingpassword.data, moderator=current_user,active='false')
        db.session.add(new_meeting)
        db.session.commit()
        return '<h1>New meeting has been created!</h1>'

    return render_template('new-meeting.html',form=form , name=current_user.username)

@app.route('/manage-meetings', methods=['GET', 'POST'])
@login_required
def manage_meetings():
    return render_template('manage-meetings.html', name=current_user.username, meetings=current_user.meetings)

@app.route('/rooms', methods=['GET', 'POST'])
@login_required
def rooms():
    isAdmin=current_user.usertype=='admin'
    return render_template('rooms.html', name=current_user.username, meetings=current_user.rooms, isAdmin=isAdmin)


@app.route('/dashboard')
@login_required
def dashboard():
    isAdmin=current_user.usertype=='admin'
    return render_template('dashboard.html', name=current_user.username, isAdmin=isAdmin)


@app.route('/dash')
@login_required
def dash():
    return render_template('dash.html', name=current_user.username)


@app.route('/meeting/<int:meeting_id>', methods=['GET', 'POST'])
@login_required
def meeting(meeting_id):
    meeting=Meeting.query.get_or_404(meeting_id)
    isAdmin=current_user.usertype=='admin'
    if current_user.usertype=='admin':
        meeting.active='true'
        db.session.commit()
        return render_template('meeting.html',isAdmin=isAdmin, name=current_user.username, email=current_user.email, meeting_id=meeting.id, meetingname=meeting.meetingname, meetingpassword=meeting.password, active=meeting.active)
    return '<h1>permission dinied you are not the host!</h1>'
        

@app.route('/meeting-guest/<int:meeting_id>', methods=['GET', 'POST'])
@login_required
def meeting_guest(meeting_id):
    meeting=Meeting.query.get_or_404(meeting_id)
    isAdmin=current_user.usertype=='admin'
    if meeting.active=='true':
        return render_template('meeting-guest.html', isAdmin=isAdmin, name=current_user.username, email=current_user.email, meeting_id=meeting.id, meetingname=meeting.meetingname, meetingpassword=meeting.password, active=meeting.active)
    return '<h1>This meeting has not started yet!</h1>'



@app.route('/edit-meeting/<int:meeting_id>', methods=['GET', 'POST'])
@login_required
def edit_meeting(meeting_id):
    form = UserForm()
    meeting=Meeting.query.get_or_404(meeting_id)
    isAdmin=current_user.usertype=='admin'
    meeting_guests=meeting.guests
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        meeting.guests.append(user)
        db.session.commit()
        return render_template('edit-meeting.html',form=form, isAdmin=isAdmin, name=current_user.username, meeting_id=meeting.id, meetingname=meeting.meetingname, meetingpassword=meeting.password, active=meeting.active, meeting_guests=meeting_guests)
    #return '<h1>User not added!</h1>'
    return render_template('edit-meeting.html',form=form, isAdmin=isAdmin, name=current_user.username, meeting_id=meeting.id, meetingname=meeting.meetingname, meetingpassword=meeting.password, active=meeting.active, meeting_guests=meeting_guests)
    




@app.route('/end-meeting/<int:meeting_id>', methods=['GET', 'POST'])
@login_required
def end_meeting(meeting_id):
    meeting=Meeting.query.get_or_404(meeting_id)
    if current_user.usertype=='admin':
        meeting.active='false'
        db.session.commit()
        return render_template('manage-meetings.html', name=current_user.username, meetings=current_user.meetings)
    isAdmin=current_user.usertype=='admin'
    return render_template('rooms.html', name=current_user.username, meetings=current_user.rooms, isAdmin=isAdmin)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)


