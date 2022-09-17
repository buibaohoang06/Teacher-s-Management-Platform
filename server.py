from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from keygen import KeyGen
from markupsafe import escape
from blueprint import bp

app = Flask(__name__)
app.register_blueprint(bp, url_prefix="/test")
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SECRET_KEY'] = "testkey"


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    username = db.Column(db.String(length=30), nullable=False)
    hashed_password = db.Column(db.String(length=1024), nullable=False)
    group = db.Column(db.String(length=1024), nullable=False)
    points = db.Column(db.Integer(), default=100)

class Group(db.Model):
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    name = db.Column(db.String(length=30), nullable=False)
    key = db.Column(db.String(length=8), nullable=False, unique=True)
    group_admin = db.Column(db.String(length=30), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    owner = db.Column(db.String(length=30), nullable=False)
    notes = db.Column(db.String(length=30), nullable=False)
    description = db.Column(db.String(), nullable=False)
    group = db.Column(db.String(length=8), nullable=False)
    

class Blog(db.Model):
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    owner = db.Column(db.String(length=30), nullable=False)
    content = db.Column(db.String(length=1024), nullable=False)
    group = db.Column(db.String(length=8), nullable=False)
    title = db.Column(db.String(), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    group = StringField(validators=[InputRequired()], render_kw={"placeholder": "Group"})
    submit = SubmitField("Register")

    def validate_user(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("This username already exists")

class RegisterGroup(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    group_name = StringField(validators=[InputRequired()], render_kw={"placeholder": "Group Key"})
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class AssignTask(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"}) 
    notes = StringField(validators=[InputRequired()], render_kw={"placeholder": "Notes to recipient"}) 
    content = StringField(validators=[InputRequired()], render_kw={"placeholder": "Content"}) 
    submit = SubmitField("Assign Task")

class AddMember(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")


class DeleteMember(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    reason = StringField(validators=[InputRequired()], render_kw={"placeholder": "Reason"})
    submit = SubmitField("Delete Member")


class BlogPost(FlaskForm):
    title = StringField(validators=[InputRequired()], render_kw={"placeholder": "Title"})
    content = TextAreaField(validators=[InputRequired()], render_kw={"placeholder": "Content"})
    submit = SubmitField("Post")


@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html'), 404

@app.route("/")
def home():
    return render_template('home.html')


@app.route('/<key>/login', methods=['GET', 'POST'])
def login(key):
    if Group.query.filter_by(key=key).first() != None:
        if current_user.is_authenticated:
            return redirect(f'/{key}/member')
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if bcrypt.check_password_hash(user.hashed_password, form.password.data):
                login_user(user)
                return redirect(f'/{key}/member')
            else:
                return redirect(url_for(f'/{key}/login'))
    else:
        return "Invalid group key!"
    try:
        return render_template('login.html', form=form)
    except IndexError:
        return render_template('error.html'), 400


@app.route("/<key>/admin", methods=['POST', 'GET'])
@login_required
def admin(key):
    if User.query.filter_by(id=current_user.id).first().username == Group.query.filter_by(key=escape(key)).first().group_admin:
        assignTask = AssignTask()
        addMember = AddMember()
        deleteMember = DeleteMember()
        member = User.query.filter_by(group=key).all()
        if assignTask.validate_on_submit():
            user = User.query.filter_by(username=assignTask.username.data).first()
            if user != None:
                new_task = Task(owner=assignTask.username.data, notes=assignTask.notes.data, description=assignTask.content.data, group=key)
                db.session.add(new_task)
                db.session.commit()
                flash("Task sent!", 'success')
                return redirect(f'/{key}/admin')
            else:
                flash("No user found with the given name!", 'danger')
                return redirect(f'/admin/{key}')
        if addMember.validate_on_submit():
            try:
                if User.query.filter_by(group=key, username=addMember.username.data).first() is not None:
                    flash("User already exists!", 'danger')
                    return redirect(f'/{key}/admin')
                else:
                    hashed_password = bcrypt.generate_password_hash(addMember.password.data)
                    new_user = User(username=addMember.username.data, hashed_password=hashed_password, group=key)
                    db.session.add(new_user)
                    db.session.commit()
                    flash('User created!', 'success')
                    return redirect(f'/{key}/admin')
            except Exception as e:
                flash(f'Error occured: {e}', 'danger')
                return redirect(url_for('admin'))
        if deleteMember.validate_on_submit():
            user = User.query.filter_by(username=assignTask.username.data).first()
            if user != None:
                User.query.filter_by(username=deleteMember.username.data).delete()
                db.session.commit()
                flash("User deleted!", 'danger')
                return redirect(f'/{key}/admin')
            else:
                flash("No user found with the given name!", 'danger')
                return redirect(f'/{key}/admin')
        return render_template('admin.html', members=member, form=assignTask, addmember=addMember, deletemember=deleteMember, currentUser=User.query.filter_by(id=current_user.id).first().username, currentGroup=Group.query.filter_by(key=key).first().name, key=key)
    else:
        return redirect(f'/{key}/member')


@app.route("/register", methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if Group.query.filter_by(key=form.group.data).first() == None:
            flash("Group key doesn't exist!", 'danger')
            return redirect('/register')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, hashed_password=hashed_password, group=form.group.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(f'/{form.group.data}/login')
    return render_template('register.html', form=form)

@app.route("/<key>/member")
@login_required
def member(key):
    post = Blog.query.filter_by(group=key).all()
    tasks = Task.query.filter_by(group=key, owner=User.query.filter_by(id=current_user.id, group=key).first().username).all()
    if Group.query.filter_by(key=key).first() != None:
        currentUser = User.query.filter_by(id=current_user.id, group=key).first()
        return render_template('member.html', currentGroup=Group.query.filter_by(key=key).first().name, currentUser=currentUser.username, key=key, posts=post, tasks=tasks)
    else:
        return "Invalid group key!"

@app.route('/<key>/logout')
@login_required
def logout(key):
    logout_user()
    return redirect(f'/{key}/login')

@app.route('/<key>/admin/blog', methods=['POST', 'GET'])
@login_required
def blog_post(key):
    if User.query.filter_by(id=current_user.id).first().username == Group.query.filter_by(key=escape(key)).first().group_admin:
        form = BlogPost()
        if form.validate_on_submit():
            try:
                new_post = Blog(owner=User.query.filter_by(id=current_user.id, group=key).first().username, content=form.content.data, group=key, title=form.title.data)
                db.session.add(new_post)
                db.session.commit()
                flash('Posted!', 'success')
                return redirect(f'/{key}/admin/blog')
            except Exception as e:
                flash(f'Something went wrong. Error: {str(e)}', 'danger')
                return redirect(f'/{key}/admin/blog')
    else:
        return "You do not have permission to access this page."
    return render_template('post.html', form=form, currentUser=User.query.filter_by(id=current_user.id).first().username, currentGroup=Group.query.filter_by(key=key).first().name, key=key)
@app.route('/create', methods=['POST', 'GET'])
def create():
    form = RegisterGroup()
    if form.validate_on_submit():
        key = KeyGen.spawn()
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_group = Group(name=form.group_name.data, key=key, group_admin=form.username.data)
        new_user = User(username=form.username.data, hashed_password=hashed_password, group=key)
        db.session.add(new_group)
        db.session.add(new_user)
        db.session.commit()
        return redirect(f'/{key}/login')
    return render_template("creategroup.html", form=form)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)