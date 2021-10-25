from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ForgetPasswordForm, ChangePasswordForm
from hashlib import md5
from functools import wraps
import smtplib

#ENVIROMENT VARIABLES
from os import environ
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

secret_key = environ["SECRET_KEY"]
EMAIL = environ["EMAIL"]
MAIL = environ["MAIL"]
PASSWORD = environ['PASSWORD']

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
try:
    URI = environ["DATABASE_URL"]
    if (URI.startswith("postgres")):
        URI = f"postgresql{URI.split('postgres')[1]}"
    app.config["SQLALCHEMY_DATABASE_URI"] = URI
except KeyError:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///blog.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##LOGIN MANAGER
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
login_manager = LoginManager()
login_manager.init_app(app)

## This is used to store the information in current_user
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

def show_status(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = current_user
        logged_in = user.is_authenticated

        if (not user.is_anonymous):
            admin = True if user.id==1 else False
        else:
            admin = False

        return function(*args, **kwargs, admin=admin, logged_in=logged_in)
    return wrapper

def only_admin(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = current_user

        if (not user.is_anonymous):
            post_id = kwargs["post_id"]
            try:
                author_id = BlogPost.query.filter_by(id=post_id).first().author.id
                admin = True if user.id==author_id or user.id==1 else False

            except AttributeError:
                admin = False

        else:
            admin = False

        if (not admin):
            abort(403)

        return function(*args, **kwargs)
    return wrapper


#Function to send messages
def send_email_message(subject: str,body: str, mail_to_send):
    text = f"Subject: {subject}\nFrom: Mario's Blog\n{body}"
    text = text.encode("UTF-8")
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=120) as connection:
                connection.starttls()
                connection.login(user=EMAIL, password=PASSWORD)
                connection.sendmail(from_addr=EMAIL, to_addrs=mail_to_send, 
                                    msg=text)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    ## Relationship Objects
    author = relationship("User", back_populates="posts")
    ## ForeignKey extract an element of other table
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    img_user = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

#db.create_all()


@app.route('/')
@show_status
def get_all_posts(logged_in=False, admin=False):
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=logged_in, admin=admin)


@app.route('/register', methods=['POST', 'GET'])
@show_status
def register(logged_in=False, admin=False):
    form = RegisterForm()
    if (form.validate_on_submit()):
        #New_user
        email = form.email.data
        password = form.password.data
        name = form.name.data

        password = generate_password_hash(password, salt_length=8)

        #Unique email
        if (User.query.filter_by(email=email).first() == None):
            new_user = User(email=email,
                            password=password,
                            name=name,
                            img_user = f"https://www.gravatar.com/avatar/{md5(bytes(email, 'utf-8')).hexdigest()}"
            )
            #Add new_user
            db.session.add(new_user)
            db.session.commit()
        else:
            flash("You already have an account with that email", category='error')
        return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
@show_status
def login(logged_in=False, admin=False):
    form = LoginForm()
    
    ##VERIFY EMAIL AND PASSWORD
    if (request.method == "POST"):
        password = form.password.data
        email = form.email.data
        # Search email
        user = User.query.filter_by(email=email).first()
        
        # Email exists
        if (user!=None):
            if (check_password_hash(user.password, password)):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password doesn't match the user", category="error")
        else:
            print("a")
            flash("That user doesn't exist in our records", category="error")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
@show_status
def logout(logged_in=False, admin=False):
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
@show_status
def show_post(post_id, logged_in=False, admin=False):
    form  = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    comment_id=request.args.get("comment_id", None)
    print(f"Comment_id: {comment_id}")
    if (form.validate_on_submit()):
        if (not current_user.is_anonymous): 
            text = form.comment.data

            #If is a new post
            if (comment_id == None):
                new_comment = Comment(
                    author = current_user,
                    author_id = current_user.id,
                    post_id = post_id,
                    parent_post = requested_post,
                    text = text
                )

                db.session.add(new_comment)
                db.session.commit()
            else:
                #Edit comment
                print(f"Edit: {comment_id}")
                comment = Comment.query.get(int(comment_id))
                comment.text = text

                #Save data
                db.session.commit()

            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You need an account to do that", category="error")
            return redirect(url_for('login'))
    
    elif (request.args.get("comment_id") != None):
        # Retrieve data
        comment = Comment.query.get(int(comment_id))
        form = CommentForm(
            comment=comment.text,
        )

        # Tuple of data
        print(f"comment_id: {comment_id}")
        
        print(f"Text: {comment.text}")

    return render_template("post.html", post=requested_post, form=form, logged_in=logged_in, admin=admin, comment_id=comment_id)

@app.route("/profile")
@login_required
def profile(logged_in=False, admin=False):
    return render_template("profile.html", logged_in=logged_in, admin=admin)
    

@app.route("/about")
@show_status
def about(logged_in=False, admin=False):
    return render_template("about.html", logged_in=logged_in, admin=admin)


@app.route("/contact", methods=["POST", "GET"])
@show_status
def contact(logged_in=False, admin=False):
    if request.method == "POST":
        name = request.form['name']   
        mail = request.form['email']
        phone = request.form['phone']
        message = request.form["message"]

        subject = "New message"
        body = f"Name: {name}\nPhone: {phone}\nMail: {mail}\n\n\t{message}"

        send_email_message(subject=subject, body=body, mail_to_send=MAIL)
        flash("Sucessfully send message!", category="message")
    return render_template("contact.html", logged_in=logged_in, admin=admin)


@app.route("/new-post", methods=["POST", "GET"])
@show_status
def add_new_post(logged_in=False, admin=False):
    form = CreatePostForm()
    if form.validate_on_submit():
        if (current_user.is_anonymous):
            flash("You need an account to do that", category="error")
            return redirect(url_for('login'))
        #If don't exist a post with that title
        elif (BlogPost.query.filter_by(title=form.title.data).first() == None):
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                author_id = current_user.id,
                date=date.today().strftime("%B %d, %Y"),
            )

            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        else:
            flash("Already a post with that title")

    return render_template("make-post.html", form=form, logged_in=logged_in, admin=admin)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@show_status
@only_admin
def edit_post(post_id, logged_in=False, admin=False):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@show_status
@only_admin
def delete_post(post_id, logged_in=False, admin=False):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete-comment/<int:comment_id>")
@login_required
@show_status
def delete_comment(comment_id, logged_in=False, admin=False):
    request_comment = Comment.query.filter_by(id=comment_id).first()

    ##Not found comment
    if (request_comment==None):
        abort(404)
    ##Sucessfully
    elif (request_comment in current_user.comments):
        db.session.delete(request_comment)
        db.session.commit()
    ##Without authorization
    else:
        abort(403)
    
    return redirect(url_for('show_post', post_id=request_comment.post_id))

@app.route('/forget-password', methods=["POST", "GET"])
@show_status
def forget_password(logged_in=False, admin=False):
    form = ForgetPasswordForm()
    if (request.method=="POST"):
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        
        # There are an user with that email
        if (user!=None):
            #Create query
            password = user.password
            #Send password to URL
            url = f"{request.url_root[:-1]}{url_for('change_password', key=password, user_id=user.id)}"
            subject = "Reset your password"
            body = f"Hello {user.name}, enter the following link to restore your password.\nURL: {url}\nThank you very much for being part of our blog."

            send_email_message(subject="Reset your password", body=body, mail_to_send=email)

            flash("A verification message has been sent to your email", category="info")
        else:
            flash("That user doesn't exist in our records", category="error")
        return redirect(f"{url_for('forget_password')}#password")

    return render_template("forget-password.html", form=form, logged_in=logged_in, admin=admin)

##CHANGE PASSWORD
@app.route("/change-password/<key>/<int:user_id>", methods=['POST', 'GET'])
@show_status
def change_password(key, user_id, logged_in=False, admin=False):
    form = ChangePasswordForm()
    user = User.query.get(user_id)

    #Correctly verification
    if (user.password == key):
        #Change password
        if (request.method=="POST"):
            new_password = form.password.data
            new_password_salted = generate_password_hash(new_password, salt_length=8)

            user.password = new_password_salted

            db.session.commit()
            flash("Password sucessfully changed", category='info')

            return redirect(url_for('login'))

        return render_template("change-password.html", form=form, logged_in=logged_in, admin=admin, user_id=user_id, key=key)
    else:
        abort(403)

if __name__ == "__main__":
    app.run(port=5000)
