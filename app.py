from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import ast
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ----- Encryption Setup -----
KEY_FILE = "secret.key"
DATA_FILE = "user_data.dat"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    return open(KEY_FILE, "rb").read()

def save_data(users, passwords, roles):
    key = load_key()
    f = Fernet(key)
    data = str({"users": users, "passwords": passwords, "roles": roles}).encode()
    encrypted_data = f.encrypt(data)
    with open(DATA_FILE, "wb") as file:
        file.write(encrypted_data)

def load_data():
    if not os.path.exists(DATA_FILE):
        return None
    key = load_key()
    f = Fernet(key)
    with open(DATA_FILE, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    data = ast.literal_eval(decrypted_data.decode())
    return data["users"], data["passwords"], data["roles"]

# ----- Initialize Data -----
if not os.path.exists(KEY_FILE):
    generate_key()

loaded = load_data()
if loaded:
    users, passwords, roles = loaded
else:
    users = ["Admin", "Moderator", "Guest"]
    passwords = ["Admin", "Moderator", "Guest"]
    roles = ["Admin", "Moderator", "Guest"]

# ----- Routes -----
@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username in users:
        index_user = users.index(username)
        if password == passwords[index_user]:
            session["username"] = username
            session["role"] = roles[index_user]
            return redirect(url_for("dashboard"))
        else:
            flash("Please Enter Correct User Password")
    else:
        flash("Please Enter A Valid Username")
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("index"))

    combined = list(zip(users, roles))  # ✅ FIXED HERE

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        combined=combined,
    )

@app.route("/create", methods=["GET", "POST"])
def create():
    if "username" not in session:
        flash("You must log in first.")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_role = request.form["role"]

        if new_username in users:
            flash("User already exists!")
        else:
            users.append(new_username)
            passwords.append(new_password)
            roles.append(new_role)
            flash("User created successfully!")
        return redirect(url_for("dashboard"))

    return render_template("create.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/delete/<username>")
def delete(username):
    if "username" not in session or session["role"] != "Admin":
        return redirect(url_for("dashboard"))

    if username == "Admin":
        flash("You Can't Delete Default Admin User")
        return redirect(url_for("dashboard"))

    if username in users:
        index_user = users.index(username)
        del users[index_user]
        del passwords[index_user]
        del roles[index_user]
        save_data(users, passwords, roles)
        flash("User Was Successfully Deleted")
    return redirect(url_for("dashboard"))

@app.route("/edit/<username>", methods=["GET", "POST"])
def edit(username):
    if "username" not in session or session["role"] != "Admin":
        return redirect(url_for("dashboard"))

    if username not in users or username == "Admin":
        flash("The Default Admin User Can't Be Edited")
        return redirect(url_for("dashboard"))

    index_user = users.index(username)

    if request.method == "POST":
        users[index_user] = request.form.get("edit_user")
        passwords[index_user] = request.form.get("edit_password")
        roles[index_user] = request.form.get("edit_role")
        save_data(users, passwords, roles)
        flash("User Was Successfully Edited")
        return redirect(url_for("dashboard"))

    return render_template(
        "edit.html",
        username=username,
        password=passwords[index_user],
        role=roles[index_user],
    )

if __name__ == "__main__":
    app.run(debug=True)
