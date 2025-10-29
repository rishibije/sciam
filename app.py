import os
import queue
import select
import sys
import threading
import uuid
import tempfile
import subprocess
import time
import shutil
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session as flask_session
import flask
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pymysql
from pymysql.cursors import DictCursor
# Database configuration (MySQL via PyMySQL)
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', '3306'))
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'Parthavi@1204')
MYSQL_DB = os.environ.get('MYSQL_DB', 'sciam')

# Flask app initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')




def get_db():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        cursorclass=DictCursor,
        autocommit=True,
    )

def init_db():
    ddl = (
        "CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;".format(db=MYSQL_DB)
    )
    # Create database if needed (requires connection without db)
    try:
        conn_server = pymysql.connect(host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER, password=MYSQL_PASSWORD, cursorclass=DictCursor, autocommit=True)
        with conn_server.cursor() as cur:
            cur.execute(ddl)
    finally:
        try:
            conn_server.close()
        except Exception:
            pass
    # Now ensure users table exists
    create_users = (
        """
        CREATE TABLE IF NOT EXISTS users (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT,
          email VARCHAR(255) NOT NULL,
          username VARCHAR(80) NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          UNIQUE KEY uq_users_email (email),
          UNIQUE KEY uq_users_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """
    )
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(create_users)
    finally:
        conn.close()

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not flask_session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        return func(*args, **kwargs)
    return wrapper

# Use threading async_mode for better compatibility
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='threading')

# Store sessions in memory
sessions = {}
running_processes = {}
input_queues = {}
process_needs_input = {}

# Root for storing uploaded datasets per session
UPLOAD_ROOT = os.path.join(os.getcwd(), "data", "sessions")
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# Limit uploads to 200 MB per file (adjust if needed)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024

# ------------------ Models ------------------
# ------------------ Auth Helpers ------------------
def get_user_by_email_or_username(email_or_username: str):
    sql = "SELECT * FROM users WHERE email=%s OR username=%s LIMIT 1"
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (email_or_username.lower(), email_or_username))
            return cur.fetchone()
    finally:
        conn.close()

def create_user(username: str, email: str, password: str):
    password_hash = generate_password_hash(password)
    sql = "INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)"
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (email.lower(), username, password_hash))
            return cur.lastrowid
    finally:
        conn.close()

@app.route("/")
def index():
    return render_template(
        "home.html",
        is_authenticated=bool(flask_session.get('user_id')),
        username=flask_session.get('username'),
    )

# ------------------ Auth Routes ------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Support in-page modal: GET redirects to home with modal hint
    if request.method == 'GET':
        return redirect(url_for('index', show='signup'))

    # Handle POST - allow AJAX (JSON) or form-encoded
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        username = (payload.get('username') or '').strip()
        email = (payload.get('email') or '').strip().lower()
        password = payload.get('password') or ''
    else:
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

    if not username or not email or not password:
        if is_ajax:
            return jsonify(success=False, error='All fields are required'), 400
        flash('All fields are required', 'error')
        return redirect(url_for('index', show='signup'))

    existing = get_user_by_email_or_username(email) or get_user_by_email_or_username(username)
    if existing:
        if is_ajax:
            return jsonify(success=False, error='Username or email already exists'), 409
        flash('Username or email already exists', 'error')
        return redirect(url_for('index', show='signup'))

    try:
        user_id = create_user(username, email, password)
    except Exception as e:
        if is_ajax:
            return jsonify(success=False, error=f'Failed to create user: {e}'), 500
        flash('Failed to create user', 'error')
        return redirect(url_for('index', show='signup'))

    flask_session['user_id'] = user_id
    flask_session['username'] = username
    flask_session['email'] = email
    if is_ajax:
        return jsonify(success=True, username=username)
    next_url = request.args.get('next') or url_for('index')
    return redirect(next_url)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Support in-page modal: GET redirects to home with modal hint
    if request.method == 'GET':
        return redirect(url_for('index', show='login'))

    # Handle POST - allow AJAX (JSON) or form-encoded
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        email_or_username = (payload.get('email') or '').strip()
        password = payload.get('password') or ''
    else:
        email_or_username = request.form.get('email', '').strip()
        password = request.form.get('password', '')

    user = get_user_by_email_or_username(email_or_username)
    if not user or not check_password_hash(user['password_hash'], password):
        if is_ajax:
            return jsonify(success=False, error='Invalid credentials'), 401
        flash('Invalid credentials', 'error')
        return redirect(url_for('index', show='login'))

    flask_session['user_id'] = user['id']
    flask_session['username'] = user['username']
    flask_session['email'] = user['email']
    if is_ajax:
        return jsonify(success=True, username=user['username'])
    next_url = request.args.get('next') or url_for('index')
    return redirect(next_url)

@app.route('/logout')
def logout():
    flask_session.clear()
    return redirect(url_for('index'))

@app.route("/create_session", methods=["POST"])
def create_session():
    session_id = str(uuid.uuid4())[:8]
    sessions[session_id] = {
        # Multi-file structure
        "files": {
            "main.py": "# Welcome to SIREN Collaborative Editor\n# Start coding in Python...\nprint('Hello, World!')"
        },
        "active_file": "main.py",
        "participants": {},
        "host_id": None,
        "writer_id": None,
        "chat_messages": []  # Added for chat
    }
    print(f"🎉 New session created: {session_id}")
    return jsonify({"session_id": session_id})

@app.route("/editor/<session_id>")
def editor(session_id):
    if session_id not in sessions:
        return "Session not found", 404
    return render_template("editor.html", session_id=session_id, user_name=flask_session.get('username') or 'Anonymous')

@app.route("/run_code", methods=["POST"])
def run_code():
    data = request.get_json()
    code = data.get("code", "")
    session_id = data.get("session_id")
    user_input = data.get("user_input", "")
    process_id = data.get("process_id")

    # Optional parameters
    timeout_seconds = int(data.get("timeout_seconds", 120))
    timeout_seconds = max(1, min(timeout_seconds, 300))  # allow 1..300s
    use_docker = bool(data.get("use_docker", False))
    docker_packages = data.get("docker_packages", [])  # e.g. ["numpy","pandas"]

    # If this is providing input to an existing process
    if process_id and user_input:
        if process_id in input_queues:
            input_queues[process_id].put(user_input + "\n")
            return jsonify({"status": "input_sent", "message": "Input sent to process"})
        else:
            return jsonify({"status": "error", "message": "Process not found or completed"})

    try:
        # Better detection for interactive code:
        # strip triple-quoted / quoted strings and comments first, then search for real input(...) or sys.stdin
        def _strip_strings_and_comments(s):
            s = re.sub(r'(""".*?"""|\'\'\'.*?\'\'\')', '', s, flags=re.S)  # triple-quoted
            s = re.sub(r'(".*?"|\'.*?\')', '', s, flags=re.S)               # single/double quoted
            s = re.sub(r'#.*', '', s)                                       # line comments
            return s

        cleaned = _strip_strings_and_comments(code or "")
        code_needs_input = bool(re.search(r'\binput\s*\(', cleaned)) or bool(re.search(r'\bsys\.stdin\b', cleaned))
        
        # Create a unique process ID for this execution
        process_id = str(uuid.uuid4())
        
        # Create input queue for this process (keep queue present to avoid race conditions)
        input_queues[process_id] = queue.Queue()
        process_needs_input[process_id] = code_needs_input
        
        # Run the code in a separate thread to handle input and streaming
        thread = threading.Thread(
            target=run_code_with_input,
            args=(code, process_id, session_id, code_needs_input, timeout_seconds, use_docker, docker_packages)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "status": "started", 
            "process_id": process_id,
            "needs_input": code_needs_input,
            "message": "Code execution started successfully",
            "timeout_seconds": timeout_seconds,
            "use_docker": use_docker
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error starting execution: {str(e)}"})

def _normalize_windows_paths_in_string_literals(src):
    """
    Only normalize string literals that look like file paths (contain backslashes and a file extension).
    This replaces backslashes with forward-slashes inside those literals to avoid Python unicode-escape errors
    such as '\\u...' when a filename begins with 'u' (e.g. 'ultimate...').
    """
    def repl(m):
        quote = m.group(1)
        content = m.group(2)
        # only normalize if it contains backslashes and looks like a filename (has an extension)
        if "\\" in content and re.search(r'\.\w{1,5}(?:$|\W)', content):
            new_content = content.replace("\\\\", "/")
            return quote + new_content + quote
        return m.group(0)

    # handle simple single/double-quoted strings (non-greedy)
    return re.sub(r'(["\'])(.*?)(\1)', lambda m: repl(m), src, flags=re.S)

def _copy_session_datasets_to_temp(session_id, temp_dir):
    """Copy all files from data/sessions/<session_id> into temp_dir/data/ (preserve structure).
       Also mirror them under temp_dir/datasets/<session_id>/ so user code referencing the
       'datasets/<session_id>/<file>' path will find files (this matches the download URL layout)."""
    session_dir = os.path.join(UPLOAD_ROOT, session_id)
    if not os.path.isdir(session_dir):
        return
    # primary copy location
    dest_root = os.path.join(temp_dir, "data")
    os.makedirs(dest_root, exist_ok=True)
    # mirror location matching earlier download route pattern
    mirror_root = os.path.join(temp_dir, "datasets", session_id)
    os.makedirs(mirror_root, exist_ok=True)

    for root, dirs, files in os.walk(session_dir):
        rel = os.path.relpath(root, session_dir)
        target_dir = dest_root if rel == "." else os.path.join(dest_root, rel)
        mirror_dir = mirror_root if rel == "." else os.path.join(mirror_root, rel)
        os.makedirs(target_dir, exist_ok=True)
        os.makedirs(mirror_dir, exist_ok=True)
        for f in files:
            src = os.path.join(root, f)
            dst = os.path.join(target_dir, f)
            mirror_dst = os.path.join(mirror_dir, f)
            try:
                shutil.copy2(src, dst)
            except Exception:
                pass
            try:
                shutil.copy2(src, mirror_dst)
            except Exception:
                pass

def run_code_with_input(code, process_id, session_id, code_needs_input, timeout_seconds=120, use_docker=False, docker_packages=None):
    """Run Python code with live stdout/stderr streaming. Optional Docker execution."""
    process = None
    temp_filename = None
    temp_dir = None
    
    try:
        docker_packages = docker_packages or []
        # Create a temp directory (helps for Docker volume mount)
        temp_dir = tempfile.mkdtemp(prefix="siren_exec_")
        temp_filename = os.path.join(temp_dir, "program.py")

        # Normalize potential Windows backslash paths inside string literals (conservative)
        safe_code = _normalize_windows_paths_in_string_literals(code)

        with open(temp_filename, "w", encoding="utf-8") as tmp:
            tmp.write(safe_code)
            tmp.flush()

        # Copy session datasets into the execution folder so code can access them at ./data/...
        try:
            _copy_session_datasets_to_temp(session_id, temp_dir)
            if os.path.isdir(os.path.join(temp_dir, "data")):
                socketio.emit("code_output", {
                    "process_id": process_id,
                    "output": "📁 Session datasets were copied into the execution workspace at ./data/ and ./datasets/<session_id>/\n",
                    "type": "system"
                }, room=session_id)
        except Exception:
            pass

        # Prepare command: either local python or docker run
        if use_docker:
            # Check docker availability
            if shutil.which("docker") is None:
                socketio.emit("code_output", {
                    "process_id": process_id,
                    "output": "⚠️ Docker not found on server, falling back to local execution.\n",
                    "type": "system"
                }, room=session_id)
                use_docker = False

        if use_docker:
            # Build pip install string if packages requested
            pip_cmd = ""
            if docker_packages:
                # join packages safely
                pip_cmd = "pip install --no-cache-dir " + " ".join(docker_packages) + " >/dev/null 2>&1 && "
            # Docker volume mounting: map temp_dir -> /workspace
            container_cmd = f"{pip_cmd}python /workspace/program.py"
            cmd = [
                "docker", "run", "--rm", "-i",
                "-v", f"{temp_dir}:/workspace",
                "-w", "/workspace",
                "python:3.11-slim",
                "bash", "-lc", container_cmd
            ]
            stdin_pipe = subprocess.PIPE if code_needs_input else None
        else:
            cmd = [sys.executable, temp_filename]
            stdin_pipe = subprocess.PIPE if code_needs_input else None

        # Start subprocess
        process = subprocess.Popen(
            cmd,
            stdin=stdin_pipe,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=temp_dir
        )
        running_processes[process_id] = process

        # Notify clients that execution started
        socketio.emit("code_output", {
            "process_id": process_id,
            "output": "🚀 Code execution started...\n",
            "type": "system"
        }, room=session_id)

        # Helper to stream a single stream (stdout/stderr)
        def stream_reader(stream, stream_type):
            try:
                for line in iter(stream.readline, ''):
                    if not line:
                        break
                    socketio.emit("code_output", {
                        "process_id": process_id,
                        "output": line,
                        "type": stream_type
                    }, room=session_id)
            except Exception as e:
                # best-effort emit
                socketio.emit("code_output", {
                    "process_id": process_id,
                    "output": f"\n❌ Stream read error: {e}\n",
                    "type": "error"
                }, room=session_id)

        # Start streaming threads
        stdout_thread = threading.Thread(target=stream_reader, args=(process.stdout, "stdout"))
        stderr_thread = threading.Thread(target=stream_reader, args=(process.stderr, "stderr"))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()

        # Main loop: monitor process and handle input queue
        start_time = time.time()
        while True:
            if process.poll() is not None:
                break  # process finished

            # Timeout enforcement
            if time.time() - start_time > timeout_seconds:
                try:
                    process.kill()
                except Exception:
                    pass
                socketio.emit("code_output", {
                    "process_id": process_id,
                    "output": f"\n⏰ Error: Code execution timed out ({timeout_seconds} seconds)\n",
                    "type": "error"
                }, room=session_id)
                break

            # Try to send input if available
            try:
                user_input = input_queues[process_id].get(timeout=0.1)
                if process.stdin:
                    try:
                        process.stdin.write(user_input)
                        process.stdin.flush()
                        socketio.emit("input_received", {
                            "process_id": process_id
                        }, room=session_id)
                    except BrokenPipeError:
                        # process ended, ignore
                        pass
            except queue.Empty:
                pass
            except KeyError:
                # input queue removed/cleanup race
                break

            time.sleep(0.05)

        # Wait a short time for streaming threads to finish sending remaining output
        try:
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
        except Exception:
            pass

        # Send completion signal
        socketio.emit("code_complete", {
            "process_id": process_id,
            "status": "completed" if process.poll() is not None and process.returncode == 0 else "finished"
        }, room=session_id)

    except Exception as e:
        socketio.emit("code_output", {
            "process_id": process_id,
            "output": f"\n❌ Execution error: {str(e)}\n",
            "type": "error"
        }, room=session_id)
    finally:
        # Cleanup
        if process_id in running_processes:
            del running_processes[process_id]
        if process_id in input_queues:
            try:
                del input_queues[process_id]
            except KeyError:
                pass
        if process_id in process_needs_input:
            try:
                del process_needs_input[process_id]
            except KeyError:
                pass
        # terminate process if still alive
        try:
            if process and process.poll() is None:
                process.kill()
        except Exception:
            pass
        # remove temp files/dir
        try:
            if temp_filename and os.path.exists(temp_filename):
                os.unlink(temp_filename)
            if temp_dir and os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except Exception:
            pass

# Add a new endpoint to provide input to running process
@app.route("/provide_input", methods=["POST"])
def provide_input():
    data = request.get_json()
    process_id = data.get("process_id")
    user_input = data.get("user_input", "")
    
    if not process_id or not user_input:
        return jsonify({"status": "error", "message": "Process ID and input are required"})
    
    if process_id in input_queues:
        input_queues[process_id].put(user_input + "\n")
        return jsonify({"status": "success", "message": "Input sent to process"})
    else:
        return jsonify({"status": "error", "message": "Process not found or completed"})


@socketio.on("connect")
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on("disconnect")
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    handle_user_leave()

@socketio.on("join_session")
def handle_join(data):
    session_id = data.get("session_id")
    # Prefer logged-in user name (from Flask session), fallback to client-provided name
    name = (flask_session.get('username') or data.get("name", "Anonymous"))
    sid = request.sid
    
    if session_id not in sessions:
        emit("error", {"msg": "Session not found"})
        return
    
    join_room(session_id)
    session = sessions[session_id]
    
    # Set as host and writer if first user
    if not session["participants"]:
        session["host_id"] = sid
        session["writer_id"] = sid
        print(f"👑 {name} is now host of session {session_id}")
    
    session["participants"][sid] = {
        "name": name,
        "sid": sid
    }
    
    # Send current files and active tab to new user
    emit("session_files", {
        "files": session.get("files", {}),
        "active_file": session.get("active_file", "main.py")
    })
    
    # Send chat history to new user
    if session["chat_messages"]:
        emit("chat_history", {"messages": session["chat_messages"][-50:]})
    
    # Notify all users about updated participants
    emit_participants_update(session_id)
    
    print(f"👤 {name} joined session {session_id}")

def handle_user_leave():
    """Handle when a user leaves the session"""
    sid = request.sid
    for session_id, session in sessions.items():
        if sid in session["participants"]:
            user_name = session["participants"][sid]["name"]
            
            # Remove user from participants
            del session["participants"][sid]
            
            # Handle host transfer if host left
            if session["host_id"] == sid:
                if session["participants"]:
                    # Transfer host to first available participant
                    new_host_sid = next(iter(session["participants"].keys()))
                    session["host_id"] = new_host_sid
                    session["writer_id"] = new_host_sid
                    new_host_name = session["participants"][new_host_sid]["name"]
                    print(f"👑 Host transferred to {new_host_name} in session {session_id}")
                else:
                    # No participants left, clear host
                    session["host_id"] = None
                    session["writer_id"] = None
            
            # Update all clients
            emit_participants_update(session_id)
            
            print(f"👤 {user_name} left session {session_id}")
            break

def emit_participants_update(session_id):
    """Send updated participants list to all clients in the session"""
    if session_id in sessions:
        session = sessions[session_id]
        emit("participants_update", {
            "participants": session["participants"],
            "writer_id": session["writer_id"],
            "host_id": session["host_id"]
        }, room=session_id)

# Add these WebRTC signaling handlers to your existing app.py

@socketio.on("get_participants")
def handle_get_participants(data):
    """Get all participants in session"""
    session_id = data.get("session_id")
    sid = request.sid
    
    if session_id in sessions:
        session = sessions[session_id]
        # Notify about existing participants
        emit("participants_update", {
            "participants": session["participants"],
            "writer_id": session["writer_id"],
            "host_id": session["host_id"]
        })

@socketio.on("code_change")
def handle_code_change(data):
    session_id = data.get("session_id")
    content = data.get("content", "")
    file_name = data.get("file_name") or data.get("file") or None
    sid = request.sid
    
    if session_id in sessions:
        session = sessions[session_id]
        # Only allow the current writer to make changes
        if session["writer_id"] == sid:
            target_file = file_name or session.get("active_file", "main.py")
            if "files" not in session:
                session["files"] = {}
            if target_file not in session["files"]:
                session["files"][target_file] = ""
            session["files"][target_file] = content
            emit("code_update", {"file_name": target_file, "content": content}, room=session_id, include_self=False)
            author = session['participants'].get(sid, {}).get('name', 'unknown')
            print(f"📝 Code updated in {target_file} by {author} in session {session_id}")

@socketio.on("add_tab")
def handle_add_tab(data):
    """Host or writer can add a new file tab."""
    session_id = data.get("session_id")
    requested_name = (data.get("file_name") or "").strip() or None
    sid = request.sid
    if session_id not in sessions:
        emit("error", {"msg": "Session not found"})
        return
    session = sessions[session_id]
    if sid not in (session.get("host_id"), session.get("writer_id")):
        emit("error", {"msg": "Only host or writer can add files"})
        return
    base_name = requested_name or "file.py"
    name = base_name
    i = 2
    if "files" not in session:
        session["files"] = {}
    while name in session["files"]:
        if "." in base_name:
            stem, ext = base_name.rsplit(".", 1)
            name = f"{stem}{i}.{ext}"
        else:
            name = f"{base_name}{i}"
        i += 1
    session["files"][name] = ""
    emit("tab_added", {"file_name": name, "content": ""}, room=session_id)
    print(f"➕ Tab added {name} in session {session_id}")

@socketio.on("remove_tab")
def handle_remove_tab(data):
    """Host or writer: remove a file tab (cannot remove last file)."""
    session_id = data.get("session_id")
    file_name = (data.get("file_name") or "").strip()
    sid = request.sid
    if session_id not in sessions:
        emit("error", {"msg": "Session not found"})
        return
    session = sessions[session_id]
    if sid not in (session.get("host_id"), session.get("writer_id")):
        emit("error", {"msg": "Only host or writer can remove files"})
        return
    if not file_name or file_name not in session.get("files", {}):
        emit("error", {"msg": "File not found"})
        return
    if len(session["files"]) <= 1:
        emit("error", {"msg": "Cannot remove the last file"})
        return
    was_active = session.get("active_file") == file_name
    del session["files"][file_name]
    new_active = session.get("active_file")
    if was_active:
        new_active = sorted(session["files"].keys())[0]
        session["active_file"] = new_active
    emit("tab_removed", {"file_name": file_name, "active_file": new_active}, room=session_id)
    print(f"➖ Tab removed {file_name} in session {session_id}")

@socketio.on("rename_tab")
def handle_rename_tab(data):
    """Host or writer can rename a file tab."""
    session_id = data.get("session_id")
    old_name = (data.get("old_name") or "").strip()
    new_name = (data.get("new_name") or "").strip()
    sid = request.sid
    if session_id not in sessions:
        emit("error", {"msg": "Session not found"})
        return
    session = sessions[session_id]
    if sid not in (session.get("host_id"), session.get("writer_id")):
        emit("error", {"msg": "Only host or writer can rename files"})
        return
    if not old_name or not new_name or old_name not in session.get("files", {}):
        emit("error", {"msg": "Invalid file name"})
        return
    if new_name in session["files"] and new_name != old_name:
        emit("error", {"msg": "A file with the new name already exists"})
        return
    session["files"][new_name] = session["files"].pop(old_name)
    if session.get("active_file") == old_name:
        session["active_file"] = new_name
    emit("tab_renamed", {"old_name": old_name, "new_name": new_name}, room=session_id)
    print(f"✏️ Tab renamed {old_name} -> {new_name} in session {session_id}")

@socketio.on("tab_change")
def handle_tab_change(data):
    """Host or writer may change the active tab for the session."""
    session_id = data.get("session_id")
    file_name = (data.get("file_name") or "").strip()
    sid = request.sid
    if session_id not in sessions:
        emit("error", {"msg": "Session not found"})
        return
    session = sessions[session_id]
    if sid not in (session.get("host_id"), session.get("writer_id")):
        return
    if not file_name or file_name not in session.get("files", {}):
        return
    session["active_file"] = file_name
    emit("active_tab_changed", {"file_name": file_name}, room=session_id)
    print(f"📄 Active tab switched to {file_name} in session {session_id}")

@socketio.on("grant_write")
def handle_grant_write(data):
    """Grant write access to another user"""
    session_id = data.get("session_id")
    target_sid = data.get("target_sid")
    sid = request.sid
    
    if session_id in sessions:
        session = sessions[session_id]
        # Only host can grant write access
        if session["host_id"] == sid and target_sid in session["participants"]:
            session["writer_id"] = target_sid
            emit_participants_update(session_id)
            print(f"✏️ Write access granted to {session['participants'][target_sid]['name']}")

@socketio.on("revoke_write")
def handle_revoke_write(data):
    """Revoke write access (host becomes writer)"""
    session_id = data.get("session_id")
    sid = request.sid
    
    if session_id in sessions:
        session = sessions[session_id]
        # Only host can revoke write access
        if session["host_id"] == sid:
            session["writer_id"] = sid
            emit_participants_update(session_id)
            print(f"✏️ Write access revoked by {session['participants'][sid]['name']}")

# WebRTC signaling handlers (for future audio implementation)
@socketio.on("webrtc_offer")
def handle_webrtc_offer(data):
    target_sid = data.get("target")
    offer = data.get("sdp")
    if target_sid:
        emit("webrtc_offer", {
            "sdp": offer,
            "sid": request.sid
        }, to=target_sid)

@socketio.on("webrtc_answer")
def handle_webrtc_answer(data):
    target_sid = data.get("target")
    answer = data.get("sdp")
    if target_sid:
        emit("webrtc_answer", {
            "sdp": answer,
            "sid": request.sid
        }, to=target_sid)

@socketio.on("webrtc_ice_candidate")
def handle_webrtc_ice_candidate(data):
    target_sid = data.get("target")
    candidate = data.get("candidate")
    if target_sid:
        emit("webrtc_ice_candidate", {
            "candidate": candidate,
            "sid": request.sid
        }, to=target_sid)

# ==================== CHAT FUNCTIONALITY ADDED BELOW ====================

@socketio.on("send_chat_message")
def handle_chat_message(data):
    """Handle chat messages from clients"""
    session_id = data.get("session_id")
    message_text = data.get("message", "").strip()
    sid = request.sid
    
    if not session_id or session_id not in sessions:
        return
    
    if not message_text:
        return
    
    session = sessions[session_id]
    if sid not in session["participants"]:
        return
    
    # Get sender info
    sender_info = session["participants"][sid]
    sender_name = sender_info["name"]
    
    # Create chat message
    chat_message = {
        "id": str(uuid.uuid4())[:8],
        "sender_sid": sid,
        "sender_name": sender_name,
        "message": message_text,
        "timestamp": time.time(),
        "time_display": datetime.now().strftime("%H:%M")
    }
    
    # Store message in session chat history
    session["chat_messages"].append(chat_message)
    
    # Keep only last 100 messages
    if len(session["chat_messages"]) > 100:
        session["chat_messages"] = session["chat_messages"][-100:]
    
    # Broadcast to all participants in the session
    emit("new_chat_message", chat_message, room=session_id)
    
    print(f"💬 {sender_name} sent message in session {session_id}: {message_text[:50]}...")

@socketio.on("get_chat_history")
def handle_get_chat_history(data):
    """Send chat history to joining user"""
    session_id = data.get("session_id")
    sid = request.sid
    
    if session_id in sessions and sessions[session_id]["chat_messages"]:
        session = sessions[session_id]
        chat_history = session["chat_messages"][-50:]  # Last 50 messages
        emit("chat_history", {"messages": chat_history})

@app.route("/upload_dataset", methods=["POST"])
def upload_dataset():
    """
    Upload a dataset file for a session.
    Expects multipart/form-data with fields:
      - session_id
      - file (the file to upload)
    """
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    file = request.files["file"]
    session_id = request.form.get("session_id")
    if not session_id:
        return jsonify({"status": "error", "message": "session_id is required"}), 400
    if session_id not in sessions:
        return jsonify({"status": "error", "message": "Session not found"}), 404
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400

    filename = secure_filename(file.filename)
    session_dir = os.path.join(UPLOAD_ROOT, session_id)
    os.makedirs(session_dir, exist_ok=True)

    save_path = os.path.join(session_dir, filename)
    try:
        file.save(save_path)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to save file: {e}"}), 500

    return jsonify({"status": "success", "filename": filename, "message": "Uploaded"})


@app.route("/list_datasets", methods=["GET"])
def list_datasets():
    """
    List uploaded dataset files for a session.
    Query: ?session_id=<id>
    """
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"status": "error", "message": "session_id is required"}), 400
    session_dir = os.path.join(UPLOAD_ROOT, session_id)
    files = []
    if os.path.isdir(session_dir):
        for root, _, filenames in os.walk(session_dir):
            for fn in filenames:
                rel_dir = os.path.relpath(root, session_dir)
                rel_path = fn if rel_dir == "." else os.path.join(rel_dir, fn)
                files.append(rel_path.replace("\\", "/"))
    return jsonify({"status": "success", "files": files})


@app.route("/datasets/<session_id>/<path:filename>", methods=["GET"])
def download_dataset(session_id, filename):
    """Download a dataset file for a session (safe send)."""
    session_dir = os.path.join(UPLOAD_ROOT, session_id)
    if not os.path.isdir(session_dir):
        return "Not found", 404
    # send_from_directory will validate and safely serve
    return flask.send_from_directory(session_dir, filename, as_attachment=True)


def _copy_session_datasets_to_temp(session_id, temp_dir):
    """Copy all files from data/sessions/<session_id> into temp_dir/data/ (preserve structure)."""
    session_dir = os.path.join(UPLOAD_ROOT, session_id)
    if not os.path.isdir(session_dir):
        return
    dest_root = os.path.join(temp_dir, "data")
    os.makedirs(dest_root, exist_ok=True)
    for root, dirs, files in os.walk(session_dir):
        rel = os.path.relpath(root, session_dir)
        target_dir = dest_root if rel == "." else os.path.join(dest_root, rel)
        os.makedirs(target_dir, exist_ok=True)
        for f in files:
            src = os.path.join(root, f)
            dst = os.path.join(target_dir, f)
            try:
                shutil.copy2(src, dst)
            except Exception:
                # best-effort, don't abort execution because of copy errors
                pass

if __name__ == "__main__":
    print("🚀 Starting SIREN Collaborative Editor...")
    print("📍 Local URL: http://localhost:5000")
    print("💡 Features: Real-time coding, Python execution, User management, Chat")
    print("🔧 Running with threading async_mode for better compatibility")
    try:
        init_db()
        print("🗄️ Database initialized (tables ensured).")
    except Exception as e:
        print(f"⚠️ DB init failed: {e}")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
