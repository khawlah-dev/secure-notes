import os
import re
from datetime import datetime

from cryptography.fernet import Fernet
from flask import Flask, jsonify, redirect, render_template_string, request
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy


def require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Set the {name} environment variable before starting the app.")
    return value


def normalize_database_uri(database_uri):
    if database_uri.startswith("postgres://"):
        return database_uri.replace("postgres://", "postgresql://", 1)
    return database_uri


def ensure_sqlite_parent(database_uri):
    if database_uri.startswith("sqlite:////"):
        database_path = "/" + database_uri.removeprefix("sqlite:////")
    elif database_uri.startswith("sqlite:///"):
        database_path = database_uri.removeprefix("sqlite:///")
    else:
        return

    if not database_path or database_path == ":memory:" or not os.path.isabs(database_path):
        return

    os.makedirs(os.path.dirname(database_path), exist_ok=True)


SECRET_ENCRYPTION_KEY = require_env("SECRET_ENCRYPTION_KEY").encode("utf-8")
cipher = Fernet(SECRET_ENCRYPTION_KEY)
DATABASE_URI = normalize_database_uri(os.environ.get("DATABASE_URL", "sqlite:///notes.db"))
ensure_sqlite_parent(DATABASE_URI)

app = Flask(__name__)
app.config["SECRET_KEY"] = require_env("FLASK_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    title = db.Column(db.String(255), default="Untitled")
    content = db.Column(db.Text, default="")
    category = db.Column(db.String(50), default="Journal")
    word_count = db.Column(db.Integer, default=0)
    is_secure = db.Column(db.Boolean, default=False)
    pin_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(100), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, default="")
    ip_address = db.Column(db.String(50), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def validate_password(password):
    requirements = []

    if len(password) < 8:
        requirements.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        requirements.append("Password must include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        requirements.append("Password must include at least one lowercase letter.")
    if not re.search(r"\d", password):
        requirements.append("Password must include at least one number.")
    if not re.search(r"[^A-Za-z0-9\s]", password):
        requirements.append("Password must include at least one special character.")
    if re.search(r"\s", password):
        requirements.append("Password cannot include spaces.")

    return requirements


def log_action(action, username=None, user_id=None, details=""):
    log = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        details=details,
        ip_address=request.remote_addr or "",
    )
    db.session.add(log)
    db.session.commit()


LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#FDFBF7] flex min-h-screen items-center justify-center px-4 py-8">

<form method="POST" class="bg-white p-6 sm:p-10 rounded-2xl shadow w-full max-w-sm">
<h1 class="text-3xl sm:text-4xl mb-6">Login</h1>

{% if error %}
<p class="bg-red-50 text-red-700 border border-red-200 rounded-xl p-3 mb-4">{{ error }}</p>
{% endif %}

<input name="username" placeholder="Username" class="w-full border p-3 rounded-xl mb-4">
<input name="password" type="password" placeholder="Password" class="w-full border p-3 rounded-xl mb-4">

<button class="w-full bg-[#897A62] text-white p-3 rounded-xl">Login</button>
<a href="/register" class="block mt-4 text-center">Create account</a>
</form>

</body>
</html>
"""


REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#FDFBF7] flex min-h-screen items-center justify-center px-4 py-8">

<form method="POST" class="bg-white p-6 sm:p-10 rounded-2xl shadow w-full max-w-sm">
<h1 class="text-3xl sm:text-4xl mb-6">Register</h1>

{% if error %}
<p class="bg-red-50 text-red-700 border border-red-200 rounded-xl p-3 mb-4">{{ error }}</p>
{% endif %}

<input name="username" placeholder="Username" class="w-full border p-3 rounded-xl mb-4">
<input
name="password"
type="password"
placeholder="Password"
minlength="8"
autocomplete="new-password"
aria-describedby="passwordRules"
class="w-full border p-3 rounded-xl mb-3">

<ul id="passwordRules" class="text-sm text-gray-600 mb-4 list-disc pl-5 space-y-1">
<li>At least 8 characters</li>
<li>Uppercase and lowercase letters</li>
<li>At least one number</li>
<li>At least one special character</li>
<li>No spaces</li>
</ul>

<button class="w-full bg-[#897A62] text-white p-3 rounded-xl">Register</button>
<a href="/login" class="block mt-4 text-center">Already have an account?</a>
</form>

</body>
</html>
"""


AUDIT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit Logs</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#FDFBF7] min-h-screen text-[#4A4238]">

<main class="max-w-6xl mx-auto p-4 sm:p-6 lg:p-8">
<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between mb-8">
<div>
<h1 class="text-3xl sm:text-4xl font-bold">Audit Logs</h1>
<p class="text-sm text-gray-600 mt-2">Important security actions for your account.</p>
</div>
<a href="/notes" class="bg-[#9A8B72] text-white px-5 py-3 rounded-xl text-center">Back to Notes</a>
</div>

<div class="bg-white border rounded-2xl overflow-x-auto">
<table class="w-full min-w-[760px] text-left">
<thead class="bg-[#F9F5EC]">
<tr>
<th class="p-4">Time</th>
<th class="p-4">Action</th>
<th class="p-4">Username</th>
<th class="p-4">IP Address</th>
<th class="p-4">Details</th>
</tr>
</thead>
<tbody>
{% for log in logs %}
<tr class="border-t">
<td class="p-4 whitespace-nowrap">{{ log.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
<td class="p-4 font-semibold">{{ log.action }}</td>
<td class="p-4">{{ log.username or '-' }}</td>
<td class="p-4">{{ log.ip_address or '-' }}</td>
<td class="p-4">{{ log.details or '-' }}</td>
</tr>
{% else %}
<tr>
<td class="p-6 text-center text-gray-500" colspan="5">No audit logs yet.</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>
</main>

</body>
</html>
"""


NOTES_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Journal</title>
<script src="https://cdn.tailwindcss.com"></script>

<style>
body{
font-family: Georgia, serif;
background:#FDFBF7;
color:#4A4238;
}
button,
a,
input,
textarea{
touch-action: manipulation;
}
textarea{
resize:none;
}
.dark{
background:#1A1612;
color:#C4B49A;
}
.dark .panel{
background:#211D18;
border-color:#2E2820;
}
.dark .sidebar{
background:#1C1814;
}
.dark .mobile-backdrop{
background:rgba(0,0,0,.62);
}
.dark input,
.dark textarea{
color:#C4B49A;
}
@media (max-width: 767px){
body{
min-height:100vh;
}
.mobile-panel{
min-height:100vh;
height:auto !important;
margin:0 !important;
border-radius:0 !important;
border-left:0 !important;
border-right:0 !important;
}
.mobile-sidebar{
position:fixed;
top:0;
left:0;
bottom:0;
z-index:40;
width:min(86vw, 360px) !important;
min-width:0 !important;
max-width:360px !important;
height:100vh;
transform:translateX(-100%);
transition:transform .24s ease;
box-shadow:18px 0 36px rgba(74,66,56,.18);
border-right:0;
border-bottom:0;
overflow-y:auto;
}
.mobile-notes-list{
max-height:none;
}
.mobile-editor{
min-height:100vh;
}
.mobile-backdrop{
display:none;
position:fixed;
inset:0;
z-index:30;
background:rgba(26,22,18,.36);
}
body.menu-open{
overflow:hidden;
}
body.menu-open .mobile-sidebar{
transform:translateX(0);
}
body.menu-open .mobile-backdrop{
display:block;
}
}
</style>
</head>

<body>

<div class="panel mobile-panel min-h-screen h-auto md:min-h-0 md:h-[95vh] m-0 md:m-5 rounded-none md:rounded-3xl border border-l-0 border-r-0 md:border-l md:border-r flex flex-col md:flex-row overflow-hidden bg-[#FCF9F2]">

<button id="notesBackdrop" type="button" class="mobile-backdrop md:hidden" aria-label="Close notes menu"></button>

<div id="notesMenu" class="sidebar mobile-sidebar w-full md:w-[28%] md:min-w-[280px] md:max-w-[380px] bg-[#F9F5EC] border-b md:border-b-0 md:border-r p-4 md:p-6 flex flex-col" aria-label="Notes menu">

<div class="flex items-start justify-between mb-5 md:mb-6 gap-3">
<div>
<h1 class="text-3xl md:text-3xl font-bold">My Journal</h1>
</div>
<button id="closeNotesMenu" type="button" class="md:hidden border rounded-full px-4 py-2 text-sm" aria-label="Close notes menu">
Close
</button>
</div>

<div class="flex flex-wrap gap-2 sm:gap-3 items-center mb-5 md:mb-6">
<button id="toggleDark" type="button" class="text-sm underline px-1 py-2">Dark</button>
<a href="/audit" class="text-sm underline px-1 py-2">Audit</a>
<a href="/logout" class="text-sm underline px-1 py-2">Logout</a>
</div>

<input id="search" placeholder="Search notes..." class="border rounded-full px-5 py-3 mb-4 md:mb-6 bg-white/80 w-full">

<div id="notesList" class="mobile-notes-list space-y-3 md:space-y-4 flex-1 overflow-y-auto pr-1">

{% for note in notes %}
<a href="/notes?note={{ note.id }}" class="block note-card">

<div class="p-4 rounded-2xl min-h-[112px] {% if active and note.id == active.id %}border bg-white text-[#4A4238]{% endif %}">

<div class="flex justify-between gap-3">
<h3 class="font-semibold truncate">{{ note.title }}</h3>
{% if note.is_secure %}<span>Lock</span>{% endif %}
</div>

<p class="text-sm text-gray-500 mt-2">
{% if note.is_secure %}
Private entry
{% else %}
{{ note.preview }}
{% endif %}
</p>

<p class="text-xs mt-3">{{ note.updated_at.strftime('%Y-%m-%d') }}</p>

</div>

</a>
{% endfor %}

</div>

<form method="POST" action="/notes/new">
<button class="w-full mt-4 md:mt-6 bg-[#9A8B72] text-white py-4 rounded-2xl">
New Entry
</button>
</form>

</div>

<div class="mobile-editor flex-1 p-5 sm:p-6 md:p-10 relative pb-24">

<div class="md:hidden flex items-center justify-between gap-3 mb-5">
<button id="openNotesMenu" type="button" class="border rounded-full w-12 h-12 flex flex-col items-center justify-center gap-1.5" aria-controls="notesMenu" aria-expanded="false" aria-label="Open notes menu">
<span class="block w-5 h-0.5 bg-current"></span>
<span class="block w-5 h-0.5 bg-current"></span>
<span class="block w-5 h-0.5 bg-current"></span>
</button>
<span class="font-semibold truncate">{{ active.title if active else 'My Journal' }}</span>
</div>

{% if active %}

<input id="title"
value="{{ active.title }}"
class="text-3xl sm:text-4xl md:text-5xl w-full mb-5 md:mb-8 outline-none bg-transparent">

{% if active.is_secure %}

<div class="flex flex-col items-center justify-center min-h-[45vh] md:h-[70vh] text-center">
<div class="text-5xl md:text-6xl mb-4">Lock</div>
<h2 class="text-3xl sm:text-4xl md:text-5xl mb-6">This entry is locked</h2>
<button onclick="openModal()" class="bg-[#9A8B72] text-white px-8 py-4 rounded-full">
Unlock Entry
</button>
</div>

{% else %}

<textarea id="content"
class="w-full min-h-[46vh] md:h-[70vh] text-lg sm:text-xl md:text-2xl leading-8 outline-none bg-transparent">{{ decrypted_content }}</textarea>
{% endif %}

<div class="absolute bottom-5 left-5 right-5 md:left-10 md:right-10 flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3">
<span id="wordCount">{{ active.word_count }} words</span>

<button id="secureBtn"
class="bg-[#9A8B72] text-white px-6 py-3 sm:py-2 rounded-xl">
Secure Note
</button>
</div>

{% else %}

<div class="min-h-[50vh] h-full flex items-center justify-center text-center">
<form method="POST" action="/notes/new">
<p class="text-2xl sm:text-3xl mb-5">No notes yet</p>
<button class="bg-[#9A8B72] text-white px-8 py-4 rounded-full">Create First Entry</button>
</form>
</div>

{% endif %}

</div>

</div>

<div id="pinModal"
class="hidden fixed inset-0 bg-black/40 flex items-center justify-center px-4">

<div class="bg-[#F7F3EC] p-6 sm:p-10 rounded-2xl w-[500px] max-w-[92vw] text-center">

<h2 class="text-3xl sm:text-4xl mb-4">Private Entry</h2>

<input id="pinInput"
maxlength="4"
type="password"
inputmode="numeric"
pattern="[0-9]*"
class="border rounded-xl px-6 py-4 text-center text-3xl mb-6 w-full">

<div class="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center">
<button onclick="closeModal()" class="px-6 py-3">Cancel</button>

<button onclick="unlockNote()"
class="bg-[#9A8B72] text-white px-6 py-3 rounded-full">
Unlock
</button>
</div>

</div>

</div>

<script>
let timeout;

const title = document.getElementById('title');
const content = document.getElementById('content');
const activeNoteId = {{ active.id if active else 'null' }};
const openNotesMenu = document.getElementById('openNotesMenu');
const closeNotesMenu = document.getElementById('closeNotesMenu');
const notesBackdrop = document.getElementById('notesBackdrop');

function setNotesMenu(open){
document.body.classList.toggle('menu-open', open);
openNotesMenu?.setAttribute('aria-expanded', open ? 'true':'false');
}

openNotesMenu?.addEventListener('click', ()=>{
setNotesMenu(true);
});

closeNotesMenu?.addEventListener('click', ()=>{
setNotesMenu(false);
});

notesBackdrop?.addEventListener('click', ()=>{
setNotesMenu(false);
});

document.addEventListener('keydown', event=>{
if(event.key === 'Escape'){
setNotesMenu(false);
}
});

document.querySelectorAll('.note-card').forEach(card=>{
card.addEventListener('click', ()=>{
setNotesMenu(false);
});
});

function saveActiveNote(){
if(!activeNoteId || !content){
return;
}

fetch(`/notes/${activeNoteId}/save`,{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({
title:title.value,
content:content.value
})
});
}

if(content){
content.addEventListener('input', ()=>{
let words = content.value.trim().split(/\\s+/).filter(Boolean).length;
document.getElementById('wordCount').textContent = words + ' words';

clearTimeout(timeout);
timeout = setTimeout(saveActiveNote,800);
});
}

if(title && content){
title.addEventListener('input', ()=>{
clearTimeout(timeout);
timeout = setTimeout(saveActiveNote,800);
});
}

document.getElementById('secureBtn')?.addEventListener('click', ()=>{
let pin = prompt('Enter 4 digit PIN');

if(pin && pin.length === 4){
fetch(`/notes/${activeNoteId}/secure`,{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({pin})
}).then(()=>location.reload());
}
});

function openModal(){
document.getElementById('pinModal').classList.remove('hidden');
}

function closeModal(){
document.getElementById('pinModal').classList.add('hidden');
}

function unlockNote(){
fetch(`/notes/${activeNoteId}/unlock`,{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({
pin:document.getElementById('pinInput').value
})
})
.then(r=>r.json())
.then(data=>{
if(data.success){
location.reload();
}
});
}

document.getElementById('toggleDark').addEventListener('click', ()=>{
document.body.classList.toggle('dark');
localStorage.theme = document.body.classList.contains('dark') ? 'dark':'light';
});

if(localStorage.theme==='dark'){
document.body.classList.add('dark');
}

document.getElementById('search').addEventListener('input', function(){
let value = this.value.toLowerCase();

document.querySelectorAll('.note-card').forEach(card=>{
card.style.display = card.innerText.toLowerCase().includes(value) ? 'block':'none';
});
});
</script>

</body>
</html>
"""


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect("/notes")
    return redirect("/login")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        password_errors = validate_password(password)

        if not username or not password:
            error = "Please enter username and password."
        elif password_errors:
            error = " ".join(password_errors)
        elif User.query.filter_by(username=username).first():
            error = "Username already exists."
        else:
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            user = User(username=username, password_hash=hashed)
            db.session.add(user)
            db.session.commit()
            log_action(
                "REGISTER_SUCCESS",
                username=user.username,
                user_id=user.id,
                details="New user account created.",
            )
            return redirect("/login")

    return render_template_string(REGISTER_TEMPLATE, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            log_action(
                "LOGIN_SUCCESS",
                username=user.username,
                user_id=user.id,
                details="User logged in successfully.",
            )
            return redirect("/notes")

        log_action(
            "LOGIN_FAILED",
            username=username,
            user_id=user.id if user else None,
            details="Invalid username or password.",
        )
        error = "Invalid username or password."

    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route("/logout")
@login_required
def logout():
    log_action(
        "LOGOUT",
        username=current_user.username,
        user_id=current_user.id,
        details="User logged out.",
    )
    logout_user()
    return redirect("/login")


@app.route("/audit")
@login_required
def audit():
    logs = (
        AuditLog.query.filter_by(user_id=current_user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(100)
        .all()
    )

    return render_template_string(AUDIT_TEMPLATE, logs=logs)


@app.route("/notes")
@login_required
def notes():
    all_notes = (
        Note.query.filter_by(user_id=current_user.id)
        .order_by(Note.updated_at.desc())
        .all()
    )

    for note in all_notes:
        note.preview = ""

        if note.content and not note.is_secure:
            try:
                note.preview = cipher.decrypt(note.content.encode()).decode()[:40]
            except Exception:
                note.preview = ""

    note_id = request.args.get("note")
    active = None

    if note_id:
        active = Note.query.filter_by(id=note_id, user_id=current_user.id).first()

    if not active and all_notes:
        active = all_notes[0]

    decrypted_content = ""

    if active and active.content and not active.is_secure:
        try:
            decrypted_content = cipher.decrypt(active.content.encode()).decode()
        except Exception:
            decrypted_content = ""

    return render_template_string(
        NOTES_TEMPLATE,
        notes=all_notes,
        active=active,
        decrypted_content=decrypted_content,
    )


@app.route("/notes/new", methods=["POST"])
@login_required
def new_note():
    note = Note(user_id=current_user.id)
    db.session.add(note)
    db.session.commit()
    log_action(
        "NOTE_CREATED",
        username=current_user.username,
        user_id=current_user.id,
        details=f"Note ID: {note.id}",
    )
    return redirect(f"/notes?note={note.id}")


@app.route("/notes/<int:id>/save", methods=["POST"])
@login_required
def save_note(id):
    note = Note.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    title = request.json.get("title", "").strip()
    content = request.json.get("content", "")

    note.title = title if title else "Untitled"
    note.content = cipher.encrypt(content.encode()).decode()
    note.word_count = len(content.split())
    note.updated_at = datetime.utcnow()

    db.session.commit()
    log_action(
        "NOTE_UPDATED",
        username=current_user.username,
        user_id=current_user.id,
        details=f"Note ID: {note.id}",
    )

    return jsonify({"saved": True})


@app.route("/notes/<int:id>/secure", methods=["POST"])
@login_required
def secure_note(id):
    note = Note.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    pin = request.json.get("pin")

    if pin and len(pin) == 4:
        note.pin_hash = bcrypt.generate_password_hash(pin).decode("utf-8")
        note.is_secure = True
        db.session.commit()
        log_action(
            "NOTE_LOCKED",
            username=current_user.username,
            user_id=current_user.id,
            details=f"Note ID: {note.id}",
        )

    return jsonify({"locked": True})


@app.route("/notes/<int:id>/unlock", methods=["POST"])
@login_required
def unlock_note(id):
    note = Note.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    pin = request.json.get("pin")

    if note.pin_hash and bcrypt.check_password_hash(note.pin_hash, pin):
        note.is_secure = False
        db.session.commit()
        log_action(
            "NOTE_UNLOCKED",
            username=current_user.username,
            user_id=current_user.id,
            details=f"Note ID: {note.id}",
        )
        return jsonify({"success": True})

    log_action(
        "NOTE_UNLOCK_FAILED",
        username=current_user.username,
        user_id=current_user.id,
        details=f"Note ID: {note.id}",
    )
    return jsonify({"success": False})


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5003"))
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
