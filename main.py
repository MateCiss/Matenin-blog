from enum import unique
from os import error
from flask import Flask, render_template, redirect, url_for, flash, request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from sqlalchemy.exc import IntegrityError
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required, current_user, logout_user
from wtforms.validators import Email
from forms import CreatePostForm,RegisterForm, LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Gravatar
gravatar = Gravatar(app,
                    size=40,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# Configuring application
login_manager = LoginManager()
login_manager.init_app(app)

# to make the app work
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# create @admin_only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
           return abort(401, "You are not authorized to access this page.") 

        if current_user.id !=1:
            return abort(403, 'You are not allowed to access this page.')
        return f(*args, **kwargs)
    return decorated_function


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship("Comment", back_populates="author")

# db.create_all()

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship('User', back_populates='posts')
    comments = relationship("Comment", back_populates="post")
    
# db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    text = db.Column(db.Text, nullable=False)
    author = relationship("User", back_populates="comments")
    post = relationship('BlogPost', back_populates='comments')

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    is_admin = False
    if current_user.is_authenticated and current_user.id == 1:
        is_admin = True
      
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated, is_admin=is_admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST":

        # user = User.query.filter_by(email=request.form.get('email'))

        # if user:
        #     error= "You've already registered with this email. Login instead"
        #     flash(error)
        #     return redirect(url_for('login'))
        try:
            hash_and_salt_password = generate_password_hash(
                request.form.get("password"),
                method="pbkdf2:sha256",
                salt_length=8
            )

            new_user = User(
                email = request.form.get('email'),
                password = hash_and_salt_password,
                name = request.form.get('name')
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect (url_for("get_all_posts"))
        except IntegrityError:
            error= "You've already registered with this email. Login instead"
            flash(error)
            return redirect(url_for('login'))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET','POST'])
# @login_required
def login():
    form = LoginForm() 
   
    if form.email.data and form.validate_on_submit:
        email = form.email.data
        password = form.password.data

        # Find user by email entered
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                    login_user(user)
                    return redirect (url_for("get_all_posts"))
            else:
                 flash('password incorrect. Please try again!')
                 return redirect(url_for("login"))
        else:
           flash('This email does not exist!')
           return redirect(url_for('login'))

    return render_template("login.html", form=form,logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if current_user.is_authenticated :
        if request.method=="POST":
            new_comment = Comment(
                text = request.form.get('comment'),
                author = current_user,
                author_id = current_user.id,
                post = requested_post,
                post_id = post_id
            )
            db.session.add(new_comment)
            db.session.commit()
    else:
        flash('You should logged in before!')
        return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, comments=requested_post.comments,form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            author_id= current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
