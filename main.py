from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import md5
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

# database schemas need to be defined early during the development process. Once an application has launched and
# accumulated lots of data, you will need to preserve this data by migrating to the new database.
# https://www.geeksforgeeks.org/python-functools-wraps-function/
'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def admin_only(fun):
    @wraps(fun)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        else:
            return fun(*args, **kwargs)

    return wrapper


def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        # if not current_user.is_authenticated: # just use l@login_required
        # return abort(403)
        user = db.session.execute(db.select(Comment).where(Comment.author_id == current_user.id)).scalar()
        if current_user.id != user.author_id:
            return abort(403)
        return function(*args, **kwargs)

    return check


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    author: Mapped["User"] = relationship("User", back_populates="posts")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="parent_blog",
                                                     cascade="all, delete-orphan")


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), unique=False, nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), unique=False, nullable=False)
    # posts: Mapped[list[BlogPost]] = relationship("BlogPost", back_populates="post_author")
    posts: Mapped[list[BlogPost]] = relationship(BlogPost, back_populates="author")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, unique=False, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    comment_author: Mapped["User"] = relationship("User", back_populates="comments")
    blog_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_blog: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    my_form = RegisterForm()
    if my_form.validate_on_submit():
        email = my_form.email.data
        found_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if found_user:
            flash("User already registered!Please log in.")
            return redirect(url_for("login"))
        else:
            hashed_password = generate_password_hash(my_form.password.data, "pbkdf2", 8)
            new_user = User(
                email=email,
                password=hashed_password,
                name=my_form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", my_form=my_form, is_logged=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        found_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not found_user:
            flash("Email incorrect!Try again.")
            return redirect(url_for("login"))  # render_template("login.html", login_form=login_form)
        user_pwd = found_user.password
        if check_password_hash(user_pwd, login_form.password.data):
            login_user(found_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("Password incorrect!Try again.")
            return redirect(url_for("login"))
    return render_template("login.html", login_form=login_form,
                           is_logged=current_user.is_authenticated)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    admin = False
    if current_user.is_authenticated:
        if current_user.id == 1:
            admin = True
    return render_template("index.html",
                           all_posts=posts,
                           is_logged=current_user.is_authenticated,
                           admin=admin,
                           curr_user=current_user)


def avatar(email):
    digest = md5(email.lower().encode('utf-8')).hexdigest()
    return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={100}'


def gravatar(email, size=100, default='identicon', rating='g'):
    email_hash = md5(email.lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d={default}&r={rating}"
    return gravatar_url


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    admin = False
    is_logged = current_user.is_authenticated
    if is_logged:
        if current_user.id == 1:
            admin = True
    if comment_form.validate_on_submit():  # POST
        if not is_logged:
            flash("To comment you must be logged. Please, log in first.")
            return redirect(url_for("login"))
        else:
            comment_text = comment_form.comment_field.data
            new_comment = Comment(
                text=comment_text,
                blog_id=post_id,
                author_id=current_user.id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))

    gravatar_urls = {comment.comment_author.id: gravatar(comment.comment_author.email)
                     for comment in requested_post.comments}
    return render_template("post.html",
                           post=requested_post,
                           is_logged=current_user.is_authenticated,
                           curr_user=current_user,
                           admin=admin,
                           comment_form=comment_form,
                           gravatar_urls=gravatar_urls)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
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
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_logged=current_user.is_authenticated,
                           curr_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True,
                           is_logged=current_user.is_authenticated,
                           curr_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete/<int:post_id>/comments/<int:comment_id>")
@only_commenter
@login_required
def delete_comment(post_id, comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))



@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
