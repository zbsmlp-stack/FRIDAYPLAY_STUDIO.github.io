from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
import os
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'site.db')
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    bio = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        try:
            with open('admins.txt', 'r') as f:
                admins = [line.strip() for line in f if line.strip()]
            return self.username in admins
        except FileNotFoundError:
            return False

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user = db.relationship('User', backref='comments')

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(10), default='pending')  # pending, accepted
    sender = db.relationship('User', foreign_keys='Friend.user1_id', backref='sent_requests')
    receiver = db.relationship('User', foreign_keys='Friend.user2_id', backref='received_requests')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    deleted_for_sender = db.Column(db.Boolean, default=False)
    sender = db.relationship('User', foreign_keys='Message.sender_id', backref='sent_messages')
    receiver = db.relationship('User', foreign_keys='Message.receiver_id', backref='received_messages')

@app.route('/')
def home():
    files = File.query.all()
    return render_template('home.html', files=files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Аккаунт создан!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Ошибка входа', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not current_user.is_admin():
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_file = File(filename=filename, uploader_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            flash('Файл загружен', 'success')
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename)

@app.route('/download_chat/<path:filename>')
@login_required
def download_chat(filename):
    chat_dir = os.path.join(os.path.dirname(__file__), 'chat_uploads')
    return send_from_directory(chat_dir, filename)

@app.route('/comments/<int:file_id>', methods=['GET', 'POST'])
@login_required
def comments(file_id):
    file = File.query.get_or_404(file_id)
    if request.method == 'POST':
        content = request.form['content']
        comment = Comment(content=content, user_id=current_user.id, file_id=file_id)
        db.session.add(comment)
        db.session.commit()
        flash('Комментарий добавлен', 'success')
    comments_list = Comment.query.filter_by(file_id=file_id).all()
    return render_template('comments.html', file=file, comments=comments_list)

@app.route('/delete_comment/<int:comment_id>')
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if not current_user.is_admin():
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('comments', file_id=comment.file_id))
    db.session.delete(comment)
    db.session.commit()
    flash('Комментарий удален', 'success')
    return redirect(url_for('comments', file_id=comment.file_id))

@app.route('/delete_message_for_me/<int:message_id>')
@login_required
def delete_message_for_me(message_id):
    message = Message.query.get_or_404(message_id)
    if message.sender_id != current_user.id:
        flash('Нельзя удалить чужое сообщение', 'danger')
        return redirect(url_for('messages', user_id=message.receiver_id if message.sender_id == current_user.id else message.sender_id))
    message.deleted_for_sender = True
    db.session.commit()
    flash('Сообщение удалено у вас', 'success')
    return redirect(url_for('messages', user_id=message.receiver_id))

@app.route('/delete_message_for_all/<int:message_id>')
@login_required
def delete_message_for_all(message_id):
    message = Message.query.get_or_404(message_id)
    if message.sender_id != current_user.id:
        flash('Нельзя удалить чужое сообщение', 'danger')
        return redirect(url_for('messages', user_id=message.receiver_id if message.sender_id == current_user.id else message.sender_id))
    if message.file_path:
        chat_dir = os.path.join(os.path.dirname(__file__), 'chat_uploads')
        file_path = os.path.join(chat_dir, message.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.session.delete(message)
    db.session.commit()
    flash('Сообщение удалено у всех', 'success')
    return redirect(url_for('messages', user_id=message.receiver_id))

@app.route('/remove_friend/<int:user_id>')
@login_required
def remove_friend(user_id):
    friend = Friend.query.filter(
        ((Friend.user1_id == current_user.id) & (Friend.user2_id == user_id)) |
        ((Friend.user1_id == user_id) & (Friend.user2_id == current_user.id)),
        Friend.status == 'accepted'
    ).first()
    if friend:
        db.session.delete(friend)
        db.session.commit()
        flash('Друг удален', 'success')
    return redirect(url_for('friends'))

@app.route('/clear_chat/<int:user_id>', methods=['POST'])
@login_required
def clear_chat(user_id):
    chat_dir = os.path.join(os.path.dirname(__file__), 'chat_uploads')
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).all()
    for msg in messages:
        if msg.file_path:
            file_path = os.path.join(chat_dir, msg.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
    Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).delete()
    db.session.commit()
    flash('Чат очищен', 'success')
    return redirect(url_for('messages', user_id=user_id))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form['email']
        bio = request.form.get('bio', '')
        current_user.email = email
        current_user.bio = bio
        db.session.commit()
        flash('Профиль обновлен', 'success')
    return render_template('profile.html')

@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    friends_count = Friend.query.filter(
        ((Friend.user1_id == user_id) | (Friend.user2_id == user_id)),
        Friend.status == 'accepted'
    ).count()
    is_friend = Friend.query.filter(
        ((Friend.user1_id == current_user.id) & (Friend.user2_id == user_id)) |
        ((Friend.user1_id == user_id) & (Friend.user2_id == current_user.id)),
        Friend.status == 'accepted'
    ).first() is not None
    return render_template('view_profile.html', user=user, friends_count=friends_count, is_friend=is_friend)

@app.route('/add_friend/<int:user_id>')
@login_required
def add_friend(user_id):
    friend_request = Friend(user1_id=current_user.id, user2_id=user_id, status='pending')
    db.session.add(friend_request)
    db.session.commit()
    flash('Запрос в друзья отправлен', 'success')
    return redirect(url_for('home'))

@app.route('/accept_friend/<int:friend_id>')
@login_required
def accept_friend(friend_id):
    friend = Friend.query.get_or_404(friend_id)
    if friend.user2_id == current_user.id:
        friend.status = 'accepted'
        db.session.commit()
        flash('Запрос в друзья принят', 'success')
    return redirect(url_for('home'))

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def messages(user_id):
    friend = Friend.query.filter(
        ((Friend.user1_id == current_user.id) & (Friend.user2_id == user_id)) |
        ((Friend.user1_id == user_id) & (Friend.user2_id == current_user.id)),
        Friend.status == 'accepted'
    ).first()
    if not friend:
        flash('Не друзья', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        content = request.form.get('content', '')
        file = request.files.get('file')
        file_path = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            chat_dir = os.path.join(os.path.dirname(__file__), 'chat_uploads')
            os.makedirs(chat_dir, exist_ok=True)
            file.save(os.path.join(chat_dir, filename))
            file_path = filename
        if content or file_path:
            message = Message(sender_id=current_user.id, receiver_id=user_id, content=content, file_path=file_path)
            db.session.add(message)
            db.session.commit()
    friend_user = User.query.get_or_404(user_id)
    msgs = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).filter(
        ~((Message.deleted_for_sender == True) & (Message.sender_id == current_user.id))
    ).order_by(Message.timestamp).all()
    return render_template('messages.html', messages=msgs, friend_user=friend_user)

@app.route('/users')
@login_required
def users():
    search = request.args.get('search', '')
    query = User.query.filter(User.id != current_user.id)
    if search:
        query = query.filter(User.username.contains(search))
    users = query.all()
    return render_template('users.html', users=users, search=search)

@app.route('/friends')
@login_required
def friends():
    search = request.args.get('search', '')
    # Friend requests
    friend_requests = Friend.query.filter_by(user2_id=current_user.id, status='pending').all()
    # Accepted friends
    friends_rel = Friend.query.filter(
        ((Friend.user1_id == current_user.id) | (Friend.user2_id == current_user.id)),
        Friend.status == 'accepted'
    ).all()
    friends_list = []
    for f in friends_rel:
        if f.user1_id == current_user.id:
            friends_list.append(User.query.get(f.user2_id))
        else:
            friends_list.append(User.query.get(f.user1_id))
    # Connected ids
    connected_ids = {f.id for f in friends_list}
    for r in friend_requests:
        connected_ids.add(r.user1_id)
    query = User.query.filter(User.id != current_user.id, ~User.id.in_(connected_ids))
    if search:
        query = query.filter(User.username.ilike(f'%{search}%'))
    users = query.all()
    return render_template('friends.html', users=users, search=search, friend_requests=friend_requests, friends=friends_list)

@app.route('/api/messages/<int:user_id>')
@login_required
def api_messages(user_id):
    friend = Friend.query.filter(
        ((Friend.user1_id == current_user.id) & (Friend.user2_id == user_id)) |
        ((Friend.user1_id == user_id) & (Friend.user2_id == current_user.id)),
        Friend.status == 'accepted'
    ).first()
    if not friend:
        return jsonify([])
    msgs = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).filter(
        ~((Message.deleted_for_sender == True) & (Message.sender_id == current_user.id))
    ).order_by(Message.timestamp).all()
    return jsonify([{
        'id': m.id,
        'content': m.content,
        'file_path': m.file_path,
        'timestamp': m.timestamp.strftime('%H:%M'),
        'sender_id': m.sender_id
    } for m in msgs])

def clean_old_chat_files():
    chat_dir = os.path.join(os.path.dirname(__file__), 'chat_uploads')
    if os.path.exists(chat_dir):
        now = datetime.datetime.now()
        for filename in os.listdir(chat_dir):
            file_path = os.path.join(chat_dir, filename)
            if os.path.isfile(file_path):
                file_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                if (now - file_time).days >= 7:
                    os.remove(file_path)

if __name__ == '__main__':
    clean_old_chat_files()
    with app.app_context():
        os.makedirs('instance', exist_ok=True)
        db.create_all()
    app.run(debug=True)