from flask import Flask, render_template, request, flash, redirect, url_for, send_from_directory
import boto3
from dotenv import load_dotenv
import os
from flask_admin.actions import action
from flask_mongoengine import MongoEngine
from flask_admin import Admin
from flask_admin.contrib.mongoengine import ModelView
from mongoengine import Document, connect
from mongoengine.fields import (
    EmailField,
    ListField,
    StringField,
    DateTimeField
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import quote_plus
from markupsafe import Markup
from datetime import datetime, UTC


def upload_file(file, filename):
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    try:
        response = s3_client.upload_fileobj(
            file,
            os.getenv("AWS_BUCKET_NAME"),
            filename,
            ExtraArgs={
                "ACL": "public-read",
                "ContentType": file.content_type,
            },
        )
    except Exception as e:
        print(e)
        return e
    return filename


load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1000 * 1000
#app.config['SERVER_NAME'] ="ignite-global.org"
app.secret_key = os.getenv("SECRET_KEY")

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.getenv("DB_URI"),
    strategy="fixed-window",
)

uri = os.getenv("DB_URI")
app.config['MONGODB_SETTINGS'] = {
    'db': 'test',
    'host': uri
}
db = MongoEngine(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(Document, UserMixin):
    name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)

    def get_id(self):
        return self.email

class Artwork(Document):
    name = StringField(required=True)
    email = EmailField(required=True)
    country = StringField(required=True)
    phone = StringField()
    artname = StringField(required=True)
    medium = StringField(required=True)
    caption = StringField(required=True)
    filename = StringField(required=True)

class DisplayArtwork(Document):
    name = StringField(required=True)
    email = EmailField(required=True)
    country = StringField(required=True)
    phone = StringField()
    artname = StringField(required=True)
    medium = StringField(required=True)
    caption = StringField(required=True)
    filename = StringField(required=True)
    votes = ListField(EmailField())
    published = DateTimeField(required=True)

class Message(Document):
    name = StringField(required=True)
    email = EmailField(required=True)
    message = StringField(required=True)


@login_manager.user_loader
def load_user(user_id):
    user = User.objects(email=user_id).first()
    if user:
        return user
    return None


s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)
response = s3.list_buckets()
for bucket in response["Buckets"]:
    print(f'Bucket:  {bucket["Name"]}')

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


@app.route("/")
def home():
    return render_template("index.html", artworks=DisplayArtwork.objects[:3])


@app.route("/gallery")
def gallery():
    return render_template("gallery.html", artworks=DisplayArtwork.objects)


@app.route("/contact", methods=["GET"])
def contact():
    return render_template("contact.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact", methods=["POST"])
@limiter.limit(
    "10/second",
    error_message="You have sent too many requests. Please try again tomorrow.",
)
def contact_post():
    newMessage = Message(
        name = request.form["name"],
        email = request.form["email"],
        message = request.form["message"]
    )
    newMessage.save()
    flash("Message sent successfully")
    return redirect(url_for("contact"))


@app.route("/donate")
def donate():
    return render_template("donate.html")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/submit", methods=["GET"])
def submit():
    return render_template("submit.html")

@app.route("/submit", methods=["POST"])
@limiter.limit(
    "10/second",
    error_message="You have sent too many requests. Please try again later.",
)
@login_required
def submit_post():
    if "file" not in request.files:
        flash("No file submitted")
        return redirect(url_for("submit"))
    file = request.files["file"]
    if file.filename == "":
        flash("No file selected")
        return redirect(url_for("submit"))
    if file and allowed_file(file.filename):
        filename = (
            "".join(request.form["name"].split())
            + "_"
            + "".join(request.form["artname"].split())
            + "."
            + file.filename.rsplit(".", 1)[1].lower()
        )
        if Artwork.objects(filename=filename, email=current_user.get_id()) or DisplayArtwork.objects(filename=filename, email=current_user.get_id()):
            flash(
                "You have already submitted an artwork with this name; please contact our team if you believe this is a mistake or if you would like to modify it."
            )
            return redirect(url_for("submit"))
        output = upload_file(file, filename)
        if output:
            flash(
                "Thanks for submitting! Your artwork is currently under review by our team."
            )
            print(*request.form)
            newArtwork = Artwork(
                name=request.form["name"],
                email=current_user.get_id(),
                country=request.form["country"],
                phone=request.form["phone"],
                artname=request.form["artname"],
                medium=request.form["medium"],
                caption=request.form["caption"],
                filename=quote_plus(filename),
            )
            newArtwork.save()
            return redirect(url_for("submit"))
        else:
            flash("File upload failed, please try again")
            return redirect(url_for("submit"))
    else:
        flash("Invalid file type")
        print(f"Invalid file type: {file.filename}")
        return redirect(url_for("submit"))


admin_username = str(os.getenv("ADMIN_USERNAME"))
class PendingArtworks(ModelView):
    column_editable_list = ['name', 'artname', 'medium', 'caption']
    column_searchable_list = ['name', 'email', 'phone', 'artname', 'medium', 'caption']

    def is_accessible(self):
        print(current_user.get_id())
        return current_user.is_authenticated and current_user.get_id() == admin_username
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))
    def get_query(self):
        artworks = Artwork.objects
        return artworks

    def _list_thumbnail(view, context, model, name):
        if not model.filename:
            return ''

        return Markup(
            f'<img src="https://ignite-global.s3.ap-southeast-2.amazonaws.com/{model.filename}" style="max-height: 200px;">'
        )
    column_formatters = {
        'filename': _list_thumbnail
    }

    @action('accept', 'Accept', 'Are you sure you want to accept the selected artworks?')
    def accept(self, ids):
        for _id in ids:
            artwork = Artwork.objects(id=_id).first()
            newDisplayArtwork = DisplayArtwork(
                name=artwork.name,
                email=artwork.email,
                country=artwork.country,
                phone=artwork.phone,
                artname=artwork.artname,
                medium=artwork.medium,
                caption=artwork.caption,
                filename=artwork.filename,
                published=datetime.now(UTC)
            )
            newDisplayArtwork.save(force_insert=True)
            artwork.delete()
        flash("Artworks approved successfully")
        return redirect(url_for('admin.index'))

    @action('reject', 'Reject', 'Are you sure you want to delete the selected artworks?')
    def reject(self, ids):
        print(ids)
        for _id in ids:
            artwork = Artwork.objects(id=_id).first()
            artwork.delete()
            s3.delete_object(
                Bucket=os.getenv("AWS_BUCKET_NAME"),
                Key=artwork.filename
            )
        flash("Artworks deleted successfully")
        return redirect(url_for('admin.index'))

class DisplayArtworks(ModelView):
    column_editable_list = ['name', 'artname', 'medium', 'caption']
    column_searchable_list = ['name', 'email', 'phone', 'artname', 'medium', 'caption']

    def is_accessible(self):
        print(current_user.get_id())
        return current_user.is_authenticated and current_user.get_id() == admin_username

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

    def get_query(self):
        artworks = DisplayArtwork.objects
        return artworks
    def _list_thumbnail(view, context, model, name):
        if not model.filename:
            return ''

        return Markup(
            f'<img src="https://ignite-global.s3.ap-southeast-2.amazonaws.com/{model.filename}" style="max-height: 200px;">'
        )
    def _num_votes(view, context, model, name):
        return len(model.votes)
    column_formatters = {
        'filename': _list_thumbnail,
        'votes': _num_votes
    }

    @action('remove', 'Remove', 'Are you sure you want to delete the selected artworks?')
    def reject(self, ids):
        for _id in ids:
            artwork = DisplayArtwork.objects(id=_id).first()
            s3.delete_object(
                Bucket=os.getenv("AWS_BUCKET_NAME"),
                Key=artwork.filename
            )
            artwork.delete()
        flash("Artworks deleted successfully")
        return redirect(url_for('admin.index'))

class Messages(ModelView):
    column_searchable_list = ['name', 'email', 'message']

    def is_accessible(self):
        print(current_user.get_id())
        return current_user.is_authenticated and current_user.get_id() == admin_username

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

    def get_query(self):
        messages = Message.objects
        return messages

class Users(ModelView):
    column_searchable_list = ['name', 'email']
    column_exclude_list = ['password']

    def is_accessible(self):
        print(current_user.get_id())
        return current_user.is_authenticated and current_user.get_id() == admin_username

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

    def get_query(self):
        users = User.objects
        return users

app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
admin = Admin(app, name='ignite', template_mode='bootstrap4')
admin.add_view(PendingArtworks(Artwork))
admin.add_view(DisplayArtworks(DisplayArtwork))
admin.add_view(Messages(Message))
admin.add_view(Users(User))

"""
@app.route("/ignition", methods=["GET", "POST"])
@login_required
def admin():
    if not current_user.get_id() == admin_username:
        flash("You do not have access to that page.")
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("admin.html", artworks=Artwork.objects)
    elif request.method == "POST":
        if current_user.is_authenticated:
            if request.form["action"] == "accept":
                artwork = Artwork.objects(filename=request.form["filename"]).first()
                if artwork:
                    newDisplayArtwork = DisplayArtwork(
                        name=artwork.name,
                        email=artwork.email,
                        country=artwork.country,
                        phone=artwork.phone,
                        artname=artwork.artname,
                        medium=artwork.medium,
                        caption=artwork.caption,
                        filename=artwork.filename,
                        published=datetime.now(UTC)
                    )
                    newDisplayArtwork.save(force_insert=True)
                    artwork.delete()
                    flash("Artwork approved successfully")
                    return redirect(url_for("admin"))
                flash("Something went wrong")
                return redirect(url_for("admin"))
            elif request.form["action"] == "reject":
                artwork = Artwork.objects(filename=request.form["filename"]).first()
                if artwork:
                    artwork.delete()
                    s3.delete_object(
                        Bucket=os.getenv("AWS_BUCKET_NAME"),
                        Key=request.form["filename"],
                    )
                    flash("Artwork deleted successfully")
                    return redirect(url_for("admin"))
                flash("Something went wrong")
                return redirect(url_for("admin"))
            elif request.form["action"] == "acceptall":
                for artwork in Artwork.objects:
                    newDisplayArtwork = DisplayArtwork(
                        name=artwork.name,
                        email=artwork.email,
                        country=artwork.country,
                        phone=artwork.phone,
                        artname=artwork.artname,
                        medium=artwork.medium,
                        caption=artwork.caption,
                        filename=artwork.filename,
                        published=datetime.now(UTC)
                    )
                    newDisplayArtwork.save(force_insert=True)
                    artwork.delete()
                flash("All artworks approved successfully")
                return redirect(url_for("admin"))
            elif request.form["action"] == "rejectall":
                for artwork in Artwork.objects:
                    artwork.delete()
                    s3.delete_object(
                        Bucket=os.getenv("AWS_BUCKET_NAME"), Key=artwork["filename"]
                    )
                flash("All artworks deleted successfully")
                return redirect(url_for("admin"))
"""

@app.route("/upvote", methods=["POST"])
def upvote():
    if current_user.is_authenticated:
        artwork = DisplayArtwork.objects(filename=request.form["filename"]).first()
        if artwork:
            user_email = current_user.get_id()
            if user_email in artwork.votes:
                artwork.update(pull__votes=user_email)
                return "downvoted", 200
            else:
                artwork.update(add_to_set__votes=user_email)
                return "upvoted", 200
        return "Failed to upvote", 500
    return "Login to upvote", 401


@app.route("/login", methods=["GET", "POST"])
@limiter.limit(
    "10/second", error_message="You have sent too many requests. Please try again later."
)
def login():
    dest = request.args.get("next")
    if request.method == "POST":
        user = User.objects(email=request.form['email']).first()
        print(type(user))
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            flash("Logged in successfully!")
            try:
                if dest[:4] == "http":
                    return redirect(dest)
                return redirect(url_for(dest[1:]))
            except:
                return redirect(url_for("home"))
        else:
            flash("Incorrect email or password")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit(
    "10/second",
    error_message="You have sent too many requests. Please try again tomorrow.",
)
def register():
    if request.method == "POST":
        if User.objects(email=request.form["email"]):
            flash("Email already in use")
            return redirect(url_for("register"))
        else:
            newuser = User(
                name=request.form["name"],
                email=request.form["email"],
                password=generate_password_hash(request.form["password"]),
            )
            newuser.save()
            flash("Account created successfully")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully")
    return redirect(url_for("home"))

@app.route("/legal")
def legal():
    return render_template("legal.html")

@app.route('/robots.txt')
@app.route('/sitemap.xml')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

if __name__ == "__main__":
    app.run(host="0.0.0.0", ssl_context="adhoc")

