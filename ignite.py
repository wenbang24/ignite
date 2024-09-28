from flask import Flask, render_template, request, flash, redirect, url_for
import boto3
from dotenv import load_dotenv
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from secrets import token_hex
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


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
app = Flask(__name__, subdomain_matching=True)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1000 * 1000
#app.config['SERVER_NAME'] ="ignite-global.org"
app.secret_key = token_hex()

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.getenv("DB_URI"),
    strategy="fixed-window",
)

uri = os.getenv("DB_URI")
client = MongoClient(uri, server_api=ServerApi("1"))
db = client["Ignite"]
print("Collections:")
print(db.list_collection_names())
artworks = db["Ignite"]
pending = db["Pending"]
messages = db["Messages"]
users = db["Users"]

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, id):
        self.id = id

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def is_active(self):
        return True


@login_manager.user_loader
def load_user(user_id):
    user = users.find_one({"email": user_id})
    if user:
        return User(user["email"])
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
    return render_template("index.html", artworks=tuple(artworks.find({}).sort({"votes": -1}))[:3])


@app.route("/gallery")
def gallery():
    return render_template("gallery.html", artworks=tuple(artworks.find({}).sort({"votes": -1})))


@app.route("/contact", methods=["GET"])
def contact():
    return render_template("contact.html")


@app.route("/contact", methods=["POST"])
@limiter.limit(
    "5/day;1/second",
    error_message="You have sent too many requests. Please try again tomorrow.",
)
def contact_post():
    messages.insert_one(
        {
            "name": request.form["name"],
            "email": request.form["email"],
            "message": request.form["message"],
        }
    )
    flash("Message sent successfully")
    return redirect(url_for("contact"))


@app.route("/donate")
def donate():
    return render_template("donate.html")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/submit", methods=["GET", "POST"])
@login_required
@limiter.limit(
    "5/day;1/second",
    error_message="You have sent too many requests. Please try again tomorrow.",
)
def submit():
    if request.method == "GET":
        return render_template("submit.html")
    elif request.method == "POST":
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
            if artworks.find_one({"filename": filename}) or pending.find_one(
                {"filename": filename}
            ):
                flash(
                    "You have already submitted an artwork with this name; please contact our team if you believe this is a mistake or if you would like to modify it."
                )
                return redirect(url_for("submit"))
            pending.insert_one(
                {
                    "name": request.form["name"],
                    "email": current_user.get_id(),
                    "artname": request.form["artname"],
                    "caption": request.form["caption"],
                    "filename": filename,
                    "votes": {},
                }
            )
            output = upload_file(file, filename)
            if output:
                flash(
                    "Thanks for submitting! Your artwork is currently under review by our team."
                )
                return redirect(url_for("submit"))
            else:
                flash("File upload failed, please try again")
                return redirect(url_for("submit"))
        else:
            flash("Invalid file type")
            print(f"Invalid file type: {file.filename}")
            return redirect(url_for("submit"))


admin_username = str(os.getenv("ADMIN_USERNAME"))

@app.route("/ignition", methods=["GET", "POST"])
@login_required
def admin():
    if not current_user.get_id() == admin_username:
        flash("You do not have access to that page.")
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("admin.html", artworks=tuple(pending.find({})))
    elif request.method == "POST":
        if current_user.is_authenticated:
            if request.form["action"] == "accept":
                artwork = pending.find_one({"filename": request.form["filename"]})
                if artwork:
                    artworks.insert_one(
                        {
                            "name": artwork["name"],
                            "email": artwork["email"],
                            "artname": artwork["artname"],
                            "caption": artwork["caption"],
                            "filename": artwork["filename"],
                            "votes": artwork["votes"],
                        }
                    )
                    pending.delete_one({"filename": request.form["filename"]})
                    flash("Artwork approved successfully")
                    return redirect(url_for("admin"))
                flash("Something went wrong")
                return redirect(url_for("admin"))
            elif request.form["action"] == "reject":
                artwork = pending.find_one({"filename": request.form["filename"]})
                if artwork:
                    pending.delete_one({"filename": request.form["filename"]})
                    s3.delete_object(
                        Bucket=os.getenv("AWS_BUCKET_NAME"),
                        Key=request.form["filename"],
                    )
                    flash("Artwork deleted successfully")
                    return redirect(url_for("admin"))
                flash("Something went wrong")
                return redirect(url_for("admin"))
            elif request.form["action"] == "acceptall":
                for artwork in pending.find({}):
                    artworks.insert_one(
                        {
                            "name": artwork["name"],
                            "email": artwork["email"],
                            "artname": artwork["artname"],
                            "caption": artwork["caption"],
                            "filename": artwork["filename"],
                            "votes": artwork["votes"],
                        }
                    )
                    pending.delete_one({"filename": artwork["filename"]})
                flash("All artworks approved successfully")
                return redirect(url_for("admin"))
            elif request.form["action"] == "rejectall":
                for artwork in pending.find({}):
                    pending.delete_one({"filename": artwork["filename"]})
                    s3.delete_object(
                        Bucket=os.getenv("AWS_BUCKET_NAME"), Key=artwork["filename"]
                    )
                flash("All artworks deleted successfully")
                return redirect(url_for("admin"))


@app.route("/upvote", methods=["POST"])
def upvote():
    if current_user.is_authenticated:
        artwork = artworks.find_one({"filename": request.form["filename"]})
        if artwork:
            response = None
            try:
                artwork["votes"].pop(current_user.get_id())
                response = "downvoted"
            except KeyError:
                artwork["votes"][current_user.get_id()] = True
                response = "upvoted"
            artworks.update_one(
                {"filename": request.form["filename"]},
                {"$set": {"votes": artwork["votes"]}},
            )
            return response, 200
        return "Failed to upvote", 500
    return "Login to upvote", 401


@app.route("/login", methods=["GET", "POST"])
@limiter.limit(
    "2/second", error_message="You have sent too many requests. Please try again later."
)
def login():
    dest = request.args.get("next")
    if request.method == "POST":
        user = users.find_one({"email": request.form["email"]})
        if user and check_password_hash(user["password"], request.form["password"]):
            login_user(User(user["email"]))
            flash("Logged in succesfully!")
            try:
                return redirect(url_for(dest[1:]))
            except:
                return redirect(url_for("home"))
        else:
            flash("Incorrect email or password")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit(
    "3/day;1/second",
    error_message="You have sent too many requests. Please try again tomorrow.",
)
def register():
    if request.method == "POST":
        if users.find_one({"email": request.form["email"]}):
            flash("Email already in use")
            return redirect(url_for("register"))
        else:
            users.insert_one(
                {
                    "name": request.form["name"],
                    "email": request.form["email"],
                    "password": generate_password_hash(request.form["password"]),
                }
            )
            flash("Account created successfully")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host='0.0.0.0', ssl_context="adhoc")
