from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
import hashlib
from flask import jsonify


def generate_password_hash(password,method):
    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()
    
    # Update the hash object with the password string
    sha256.update(password.encode('utf-8'))
    
    # Get the hexadecimal representation of the hash
    password_hash = sha256.hexdigest()
    
    return password_hash


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:#Nikki2203@localhost/social'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TESTING'] = False
app.permanent_session_lifetime = timedelta(minutes=30)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    __tablename__ = 'User'

    UserID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(255), unique=True, nullable=False)
    Email = db.Column(db.String(255), unique=True, nullable=False)
    Pass = db.Column(db.String(255), nullable=False)
    FirstName = db.Column(db.String(255))
    LastName = db.Column(db.String(255))
    Gender = db.Column(db.Enum('F', 'M', 'f', 'm'), nullable=False)
    DateOfBirth = db.Column(db.Date)
    Bio = db.Column(db.Text)

    def __init__(self, username, email, password, first_name, last_name, gender, date_of_birth, bio):
        self.Username = username
        self.Email = email
        self.Pass = password
        self.FirstName = first_name
        self.LastName = last_name
        self.Gender = gender
        self.DateOfBirth = date_of_birth
        self.Bio = bio

    def get_id(self):
        return (self.UserID)

class Post(db.Model):
    __tablename__ = 'Post'

    PostID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    Content = db.Column(db.Text)
    Timestamps = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    PrivacySetting = db.Column(db.Enum('Public', 'Private', 'Friends-only'), nullable=False)

class Comment(db.Model):
    __tablename__ = 'Comment'

    CommentID = db.Column(db.Integer, primary_key=True)
    PostID = db.Column(db.Integer, db.ForeignKey('Post.PostID'))
    UserID = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    Content = db.Column(db.Text)
    Timestamps = db.Column(db.TIMESTAMP, default=datetime.utcnow)

class Friendship(db.Model):
    __tablename__ = 'Friendship'

    FriendshipID = db.Column(db.Integer, primary_key=True)
    UserID1 = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    UserID2 = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    Status_ = db.Column(db.Enum('Pending', 'Accepted', 'Declined'), nullable=False)

class Notification(db.Model):
    __tablename__ = 'Notification'

    NotificationID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    Content = db.Column(db.Text)
    Timestamps = db.Column(db.TIMESTAMP, default=datetime.utcnow)

class UserLike(db.Model):
    __tablename__ = 'UserLike'

    LikeID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    PostID = db.Column(db.Integer, db.ForeignKey('Post.PostID'))
    Timestamps = db.Column(db.TIMESTAMP, default=datetime.utcnow)

class Message(db.Model):
    __tablename__ = 'Message'

    MessageID = db.Column(db.Integer, primary_key=True)
    Content = db.Column(db.Text)
    Timestamps = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    SenderID1 = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    SenderID2 = db.Column(db.Integer, db.ForeignKey('User.UserID'))


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('F', 'Female'), ('M', 'Male')], validators=[DataRequired()])
    date_of_birth = StringField('Date of Birth', validators=[DataRequired()])
    bio = StringField('Bio')

    def validate_username(self, field):
        user = User.query.filter_by(Username=field.data).first()
        if user:
            raise ValidationError('Username is already in use. Please choose another one.')

    def validate_email(self, field):
        user = User.query.filter_by(Email=field.data).first()
        if user:
            raise ValidationError('Email is already in use. Please use a different email.')
                
@login_manager.user_loader
def load_user(user_id):
    # Replace this with your logic to load a user by their user_id (e.g., from the database)
    return User.query.get(int(user_id))  # Assuming User is your user model
        
# User Profile
@app.route('/profile/<user_id>')
@login_required
def profile(user_id):
    user = User.query.get(user_id)
    if user:
        return render_template('/profile', user=user)
    else:
        flash('User not found', 'error')
        return redirect(url_for('home'))

# Home Feed
@app.route('/')
@login_required
def home():
    # Query all users except the current logged-in user
    users = User.query.filter(User.UserID != current_user.UserID).all()
    posts = Post.query.all()
    return render_template('home.html', posts=posts, users=users)

# Create a Post
@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        content = request.form['content']
        if content:
            post = Post(UserID=current_user.UserID, Content=content, PrivacySetting='Public')
            db.session.add(post)
            db.session.commit()
            flash('Post created successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Please enter a post content', 'error')
    return render_template('create_post.html')
'''
# Sending Messages
@app.route('/send_message/<int:recipient_id>', methods=['GET', 'POST'])
@login_required
def send_message(recipient_id):
    recipient = User.query.get(recipient_id)
    if request.method == 'POST':
        content = request.form['content']
        if content:
            message = Message(SenderID=current_user.UserID, RecipientID=recipient_id, Content=content)
            db.session.add(message)
            db.session.commit()
            flash('Message sent successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Please enter a message', 'error')
    return render_template('send_message.html', recipient=recipient)
'''

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(Username=username).first()
        if user and user.Pass == password:
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your username and password and try again.', 'error')
    return render_template('login.html')

# Registration Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.is_submitted():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        gender = form.gender.data
        date_of_birth = form.date_of_birth.data
        bio = form.bio.data

        # Check if the username or email is already in use
        existing_user = User.query.filter_by(Username=username).first()
        existing_email = User.query.filter_by(Email=email).first()

        if existing_user:
            flash('Username already in use. Please choose another one.', 'error')
        elif existing_email:
            flash('Email already in use. Please use a different email.', 'error')
        else:
            # Create a new user with hashed password
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(
                Username=username,
                Email=email,
                Pass=hashed_password,
                FirstName=first_name,
                LastName=last_name,
                Gender=gender,
                DateOfBirth=date_of_birth,
                Bio=bio
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful', 'success')
            return redirect(url_for('login'))
    else:
        print("invalid form:", form, dir(form), form.form_errors )
    return render_template('register.html', form=form)


# User Profile Editing
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Handle form submission to update the user's profile information
        current_user.Username = request.form['username']
        current_user.FirstName = request.form['first_name']
        current_user.LastName = request.form['last_name']
        current_user.Gender = request.form['gender']
        current_user.DateOfBirth = request.form['date_of_birth']
        current_user.Bio = request.form['bio']
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile', user_id=current_user.UserID))
    return render_template('edit_profile.html')

# User Relationships
@app.route('/friends')
@login_required
def friends():
    # Retrieve the user's friends and friend requests (User Relationships)
    friends = Friendship.query.filter((Friendship.UserID1 == current_user.UserID) & (Friendship.Status_ == 'Accepted')).all()
    friend_requests = Friendship.query.filter((Friendship.UserID2 == current_user.UserID) & (Friendship.Status_ == 'Pending')).all()
    return render_template('friends.html', friends=friends, friend_requests=friend_requests)

# Post and Comment Interaction
@app.route('/post/<post_id>', methods=['GET', 'POST'])
@login_required
def view_post(post_id):
    post = Post.query.get(post_id)
    if request.method == 'POST':
        content = request.form['content']
        if content:
            comment = Comment(PostID=post.PostID, UserID=current_user.UserID, Content=content)
            db.session.add(comment)
            db.session.commit()
            flash('Comment added successfully', 'success')
            return redirect(url_for('view_post', post_id=post.PostID))
        else:
            flash('Please enter a comment', 'error')
    comments = Comment.query.filter_by(PostID=post_id).all()
    return render_template('view_post.html', post=post, comments=comments)

# Notifications
@app.route('/notifications')
@login_required
def notifications():
    # Retrieve user's notifications (Notifications)
    user_notifications = Notification.query.filter_by(UserID=current_user.UserID).all()
    return render_template('notifications.html', notifications=user_notifications)

# Join Operation to Retrieve Users and Their Posts
@app.route('/users_and_posts')
@login_required
def users_and_posts():
    users_with_posts = db.session.query(User.Username, Post.Content).join(Post).all()
    return render_template('users_and_posts.html', users_with_posts=users_with_posts)

# Union of Posts from User1 and User2
@app.route('/union_of_posts')
@login_required
def union_of_posts():
    user1_posts = Post.query.filter_by(UserID=1).all()
    user2_posts = Post.query.filter_by(UserID=2).all()
    posts_union = user1_posts + user2_posts
    return render_template('union_of_posts.html', posts_union=posts_union)



#total likes received
@app.route('/total_likes_received/<user_id>')
@login_required
def total_likes_received(user_id):
    # Use the stored function CalculateTotalLikesReceived to calculate total likes
    total_likes = db.session.query(func.CalculateTotalLikesReceived(user_id)).scalar()
    return render_template('total_likes.html', total_likes=total_likes)


# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/send_friend_request/<user_id>', methods=['POST'])
@login_required
def send_friend_request(user_id):
    # Check if a friend request already exists
    existing_request = Friendship.query.filter(
        (Friendship.UserID1 == current_user.UserID) &
        (Friendship.UserID2 == user_id)
    ).first()

    if existing_request:
        return jsonify({'status': 'error', 'message': 'Friend request already sent.'})

    # Create a new friend request
    friend_request = Friendship(UserID1=current_user.UserID, UserID2=user_id, Status_='Pending')

    # Get the sender's username
    sender_username = current_user.Username

    # Create a notification with a custom message
    notification_content = f'You have a friend request from {sender_username}'
    notification_new = Notification(UserID=user_id, Content=notification_content, Timestamps=datetime.utcnow())

    db.session.add(friend_request)
    db.session.add(notification_new)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Friend request sent successfully.'})

'''@app.before_request
def before_request():
    if current_user.is_authenticated:
        last_interaction = session.get('last_interaction')
        now = datetime.now(timezone.utc)
        
        if last_interaction is None or (now - last_interaction) > timedelta(minutes=30):
            logout_user()
            flash('Session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        session['last_interaction'] = now'''

if __name__ == '__main__':
    app.run(debug=True)