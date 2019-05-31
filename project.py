import os
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from helpers import login_required, allowed_file
import csv

UPLOAD_FOLDER = './storage/'
# Configure application
app = Flask(__name__)

# Reload templates when they are changed
app.config["TEMPLATES_AUTO_RELOAD"] = True
#set folder path
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use mysql database
db = SQL('mysql://root:01017876733@localhost/bassam')

@app.route("/")
def index():
    user_id = session.get('user_id')
    if user_id:
        rows = db.execute("SELECT * FROM contacts WHERE userid = :userid", userid=session['user_id'])
        if len(rows):
            return render_template("index.html", rows=rows)
        else:
            return render_template("indexx.html")
    else:
        return render_template("layout.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("apology.html", message = "must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("apology.html", message = "must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return render_template("apology.html", message = "invalid username or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("apology.html", message = "must provide username")
        elif not request.form.get("password"):
            return render_template("apology.html", message = "must provide password")
        elif not request.form.get("confirmation"):
            return render_template("apology.html", message = "must rebeat password")
        elif request.form.get("password") != request.form.get("confirmation"):
            return render_template("apology.html", message = "the passwords doesn't match")
        else:
            rows = db.execute("INSERT INTO users (username,password) VALUES (:userName, :password)",
                              userName=request.form.get("username"), password=generate_password_hash(request.form.get("password")))
            session['user_id'] = rows
            if not rows:
                return render_template("apology.html", message = "username is not available")
            return redirect("/")
    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/about")
@login_required
def about():
    return render_template("about.html")

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    """changing your password"""
    if request.method == "POST":
        if not request.form.get("currentpassword"):
            return render_template("apology.html", message = "missing current password")
        elif not request.form.get("newpassword"):
            return render_template("apology.html", message = "missing new password")
        elif not request.form.get("newpassword(again)"):
            return render_template("apology.html", message = "rebeat your password")
        else:
            rows = db.execute("SELECT password FROM users WHERE id = :userid", userid=session['user_id'])
            if not check_password_hash(rows[0]["password"], request.form.get("currentpassword")):
                return render_template("apology.html", message = "wrong current password")
            elif request.form.get("newpassword") != request.form.get("newpassword(again)"):
                return render_template("apology.html", message = "passwords don't match")
            else:
                rows = db.execute("UPDATE users SET password = :password WHERE id = :userid", userid=session['user_id'],
                                  password=generate_password_hash(request.form.get("newpassword")))
                return render_template("changed.html")
    else:
        return render_template("changepassword.html")

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        rows = db.execute("INSERT INTO contacts (contactname,contactphone,userid) VALUES (:contactname, :contactphone, :userid)",
                              contactname=request.form.get("contactname"), contactphone=request.form.get("contactphone"), userid = session["user_id"])
        return redirect("/")
    else:
        return render_template("add.html")

@app.route("/edit/<contactid>", methods=["GET", "POST"])
@login_required
def edit(contactid):
    if request.method == "POST":
        rows = db.execute("UPDATE contacts SET contactname = :contactname , contactphone = :contactphone  WHERE contactid = :contactid",
                          contactname =request.form.get("newcontactname"), contactphone=request.form.get("newcontactphone"), contactid= contactid )
        return redirect("/")
    else:
        row = db.execute("SELECT * FROM contacts WHERE contactid = :contactid LIMIT 1", contactid= contactid)
        return render_template("edit.html", data= row)

@app.route("/delete/<contactid>", methods=["POST"])
@login_required
def delete(contactid):
    rows = db.execute("DELETE FROM contacts WHERE contactid = :contactid", contactid = contactid)
    return redirect("/")

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            #open and save data to sql
            with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if not row["Name"] or not row["Phone 1 - Value"]:
                        continue
                    else:
                        data = db.execute("INSERT INTO contacts (contactname,contactphone,userid) VALUES (:contactname, :contactphone, :userid)",
                              contactname=row["Name"], contactphone=row["Phone 1 - Value"], userid = session["user_id"])
                        print(row['Name'],row['Phone 1 - Value'])
            csvfile.close()
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    #insert in database after check of name not empty and name has phone number
                    #return reader
                    #delete file after insert
        return redirect("/")
    else:
        return render_template("upload.html")

#not forget remove form from buttoms login / reg
