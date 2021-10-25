from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(max=100)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=100)])
    name = StringField("Name", validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField("Sign me up!")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(max=100)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=100)])
    submit = SubmitField("Log In!")

class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")

class ForgetPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(max=100)])
    submit = SubmitField("Send")

class ChangePasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    submit = SubmitField("New Password")