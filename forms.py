from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    register = SubmitField("Register")


# TODO: Create a LoginForm to login existing users

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


# TODO: Create a CommentForm so users can leave comments below posts
def decorator_a(function):
    def wrapper(*args):
        for arg in args:
            print(f"I am an arg: {arg}")
        print(f"I am the name of the function: {function.__name__}")
        print(f"{type(args)}")

        result = function(*args)
        print(f"This is the result: {result}")
        return result

    return wrapper


# @decorator_a
# def a_function(*args):
#    return sum(args)

# a_function(1,2,3)
class CommentForm(FlaskForm):
    comment_field = CKEditorField("Comment")
    submit = SubmitField("Submit")