from flask import Flask, render_template, request, redirect, url_for, session
import user_management as dbHandler
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_csp.csp import csp_default, csp_header
import re
import html
from datetime import datetime
import bcrypt
import logging
import threading
import time
import random


app = Flask(__name__)
app.secret_key="a5f8dba8cbc8d8d1c76dc1429171fc4d362242b1ec046760"

app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# CSP configuration
csp_default().update({
    "base-uri": "self",
    "default-src": "'self'",
    "style-src": "'self' https://fonts.googleapis.com",
    "style-src-attr": "'self' 'unsafe-inline'",
    "script-src": "'self' https://getfreebootstrap.ru",
    "img-src": "*",
    "media-src": "'self'",
    "font-src": "'self' https://fonts.gstatic.com",
    "object-src": "'self'",
    "child-src": "'self'",
    "connect-src": "'self'",
    "worker-src": "'self'",
    "report-uri": "/csp_report",
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "frame-src": "'none'",
})

# Logger configuration
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("logs/security_log.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security")  # Dedicated logger

#report any CSP violations to the system log.
@app.route("/csp_report", methods=["POST"])
#@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"

# Login functionality
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user_data = dbHandler.retrieveUsers(user_id)
    if user_data:
        return User(user_data["id"], user_data["username"])
    return None


visitor_lock = threading.Lock()

# Function to sanitise text using a library
def safe(string: str) -> str:
    return html.escape(string)


USERNAME_PATTERN = r"^\w{3,16}$"
PASSWORD_PATTERN = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*_=+-])[A-Za-z\d!@#$%^&*_=+-]{8,16}$"


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
@csp_header()
def home():
    # Pass message to front end
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            logger.warning("Login attempt with missing fields")
            return render_template("/index.html", error="Missing credentials"), 400

        user_data = dbHandler.retrieveUsers(username)

        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)

        if bcrypt.checkpw(password.encode(), user_data["password"]):
            # Logs in user
            user = User(user_data["id"], user_data["username"])
            login_user(user)
            logger.info(f"User login successful: {username}")
            
            # Plain text log of visitor count as requested by Unsecure PWA management
            with visitor_lock:
                with open("logs/visitor_log.txt", "r") as file:
                    number = int(file.read().strip())
                number += 1
                with open("logs/visitor_log.txt", "w") as file:
                    file.write(str(number))
            
            dbHandler.listFeedback()
            return redirect(url_for("success_page"))
        else:
            return render_template("/index.html", error="Invalid login"), 401
    else:
        return render_template("/index.html")


@app.route("/signup.html", methods=["POST", "GET"])
@csp_header()
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        dob = request.form.get("dob")
        if not username or not password or not dob:
            logger.warning(f"Signup attempt with missing fields: username={username}")
            return render_template("/signup.html", error="Missing required fields"), 400

        if not re.match(USERNAME_PATTERN, username):
            logger.warning(f"Invalid username format: {username}")
            return render_template("/signup.html", error="Invalid username format"), 400

        if not re.match(PASSWORD_PATTERN, password):
            logger.warning(f"Weak password attempt for username: {username}")
            return render_template("/signup.html", error="Password does not meet security requirements"), 400

        try:
            dob = datetime.strptime(dob, "%Y-%m-%d").date()
        except ValueError:
            logger.warning(f"Invalid DOB format for username: {username}")
            return render_template("/signup.html", error="Invalid date format (YYYY-MM-DD)"), 400
        
        try:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            dob_str = dob.strftime("%Y-%m-%d")
            dbHandler.insertUser(username, hashed, dob_str)

            logger.info(f"New user registered successfully: {username}")
            return render_template("/index.html", message="User registered successfully"), 201

        except sqlite3.IntegrityError:
            logger.warning(f"Username already exists: {username}")
            return render_template("/signup.html", error="Username already exists"), 409

        except Exception as e:
            logger.critical(f"Database error during signup for {username}: {e}")
            return render_template("/signup.html", error="Internal server error"), 500
    else:
        return render_template("/signup.html")


@app.route("/success.html", methods=["GET"])
@login_required
@csp_header()
def success_page():
    feedback_list = dbHandler.listFeedback()
    return render_template(
        "success.html",
        state=True,
        value=current_user.username,
        feedback_list=feedback_list
    )

@app.route("/add_feedback", methods=["POST"])
@login_required
@csp_header()
def add_feedback():
    if request.method == "POST":
        feedback = request.form.get("feedback", "").strip()
        # Validate feedback
        if not feedback:
            logger.warning(f"Empty feedback submitted by {current_user.username}")
            return render_template("/success.html", error="Feedback cannot be empty"), 400
        if len(feedback) > 256:
            logger.warning(f"Feedback too long by {current_user.username}")
            return render_template("/success.html", error="Feedback too long"), 400
        if len(feedback) < 8:
            logger.warning(f"Feedback too short by {current_user.username}")
            return render_template("/success.html", error="Feedback too long"), 400
        
        # Insert feedback
        dbHandler.insertFeedback(feedback)

        # Refresh feedback
        dbHandler.listFeedback()
    return redirect(url_for("success_page"))


@app.route("/logout")
@csp_header()
@login_required
def logout():
    logout_user()
    return redirect("/")  # or login page


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, use_reloader=True, host="0.0.0.0", port=5000)
