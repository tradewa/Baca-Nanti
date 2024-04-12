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