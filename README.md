# Baca Nanti - Read Later Web Applications

#### Video Demo:  https://youtu.be/7sJ16RdBhG0

### Description
Baca Nanti is an Indonesia phrase meaning Read Later in English. I created a web applications where the user can register and save their reading list for future references.


### Technology Stack Used
This web application is using flask as it's main framework and sqlite3 as its database.

### Applications Building Blocks
Baca Nanti applications has several building blocks in the applications which are:
1. Page sites
    1. Register page
    2. Login page
    3. Reading list table page
    4. Add reading list capability
    5. Delete reading list capability
    6. Logout capability
2. Database
    1. User table to save user registration
    2. Reading list table to save reading list

### Implementation
#### App initialization
```python
import os

from flask import Flask

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'bacananti.sqlite')
    )
    
    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)
        
    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'
    
    from . import db
    db.init_app(app)
    
    from . import auth
    app.register_blueprint(auth.bp)
    
    from . import bacaan
    app.register_blueprint(bacaan.bp)
    app.add_url_rule('/', endpoint='index')
    
    return app
```

#### Authorization
```python
import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash

from bacananti.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        
        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password))
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
        
        flash(error)
    
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()
        
        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)
    
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)
    
    return wrapped_view
```

#### Reading List Add, Create, Delete
```python
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, session
)
from werkzeug.exceptions import Aborter
from urllib.parse import urlparse

from bacananti.auth import login_required
from bacananti.db import get_db

bp = Blueprint('bacaan', __name__)

@bp.route('/')
def index():
    db = get_db()
    
    # Get user id for current session
    user_id = session["user_id"]
    
    bacaan = db.execute(
        'SELECT r.id, site, title, link, created, user_id, username FROM reading r JOIN user u ON r.user_id = u.id WHERE u.id = ? ORDER BY created ASC',
        (user_id,)
    ).fetchall()
    return render_template('bacaan/index.html', bacaan=bacaan)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        link = request.form['link']
        site = urlparse(link).netloc
        error = None
        
        if not title:
            error = 'Title is required.'
        
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO reading (site, title, link, user_id) VALUES (?, ?, ?, ?)',
                (site, title, link, g.user['id'])
            )
            db.commit()
            return redirect(url_for('bacaan.index'))
    return render_template('bacaan/create.html')

def get_reading(id, check_author=True):
    reading = get_db().execute(
        'SELECT r.id, site, title, link, created, user_id, username FROM reading r JOIN user u ON r.user_id = u.id WHERE r.id = ?',
        (id,)
    ).fetchone()
    
    if reading is None:
        abort(404, f"Reading id {id} doesn't exist.")
    
    if check_author and reading['user_id'] != g.user['id']:
        abort(403)
    
    return reading

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    bacaan = get_reading(id)
    
    if request.method == 'POST':
        title = request.form['title']
        link = request.form['link']
        site = urlparse(link).netloc
        error = None
        
        if not title:
            error = 'Title is required'
            
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE post SET title = ?, link = ?, site = ? WHERE id = ?',
                (title, link, site, id)
            )
            db.commit()
            return redirect(url_for('bacaan.index'))
    
    return render_template('bacaan/update.html', bacaan=bacaan)

@bp.route('/<int:id>', methods=('POST',))
@login_required
def delete(id):
    get_reading(id)
    db = get_db()
    db.execute('DELETE FROM reading WHERE id = ?', (id, ))
    db.commit()
    return redirect(url_for('bacaan.index'))
```