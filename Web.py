from flask import Flask, g, render_template, request, redirect, url_for, session, jsonify, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret-key')


def get_db():
	db = getattr(g, '_database', None)
	if db is None:
		db = g._database = sqlite3.connect(DB_PATH)
		db.row_factory = sqlite3.Row
	return db


def init_db():
	db = get_db()
	cur = db.cursor()
	cur.execute('''
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		is_admin INTEGER DEFAULT 0
	)
	''')
	cur.execute('''
	CREATE TABLE IF NOT EXISTS items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		content TEXT
	)
	''')
	db.commit()


def seed_db():
	db = get_db()
	cur = db.cursor()
	cur.execute('SELECT COUNT(*) as c FROM users')
	if cur.fetchone()['c'] == 0:
		cur.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
					('admin', generate_password_hash('admin123'), 1))
		cur.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
					('alice', generate_password_hash('password'), 0))
	cur.execute('SELECT COUNT(*) as c FROM items')
	if cur.fetchone()['c'] == 0:
		sample = [
			('First item', 'This is the first data item.'),
			('Second item', 'More content goes here.'),
			('Searchable', 'Contains searchable keyword: flask')
		]
		cur.executemany('INSERT INTO items (title, content) VALUES (?, ?)', sample)
	db.commit()


@app.teardown_appcontext
def close_connection(exception):
	db = getattr(g, '_database', None)
	if db is not None:
		db.close()


def login_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		if 'user_id' not in session:
			return redirect(url_for('login', next=request.path))
		return f(*args, **kwargs)
	return decorated


def admin_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		if 'user_id' not in session:
			return redirect(url_for('login'))
		db = get_db()
		cur = db.execute('SELECT is_admin FROM users WHERE id=?', (session['user_id'],))
		row = cur.fetchone()
		if not row or row['is_admin'] == 0:
			return "Forbidden", 403
		return f(*args, **kwargs)
	return decorated


@app.route('/')
def index():
	db = get_db()
	items = db.execute('SELECT * FROM items ORDER BY id DESC LIMIT 10').fetchall()
	user = None
	if 'user_id' in session:
		user = db.execute('SELECT id, username, is_admin FROM users WHERE id=?', (session['user_id'],)).fetchone()
	return render_template('index.html', items=items, user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form['username'].strip()
		password = request.form['password']
		if not username or not password:
			flash('用户名或密码不能为空')
			return redirect(url_for('register'))
		db = get_db()
		try:
			db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
					   (username, generate_password_hash(password)))
			db.commit()
			flash('注册成功，请登录')
			return redirect(url_for('login'))
		except sqlite3.IntegrityError:
			flash('用户名已存在')
			return redirect(url_for('register'))
	return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		db = get_db()
		cur = db.execute('SELECT * FROM users WHERE username=?', (username,))
		row = cur.fetchone()
		if row and check_password_hash(row['password'], password):
			session['user_id'] = row['id']
			flash('登录成功')
			nxt = request.args.get('next') or url_for('index')
			return redirect(nxt)
		flash('用户名或密码错误')
		return redirect(url_for('login'))
	return render_template('login.html')


@app.route('/logout')
def logout():
	session.clear()
	return redirect(url_for('index'))


@app.route('/items')
@login_required
def items():
	db = get_db()
	items = db.execute('SELECT * FROM items ORDER BY id DESC').fetchall()
	return render_template('items.html', items=items)


@app.route('/search')
@login_required
def search():
	q = request.args.get('q', '').strip()
	db = get_db()
	if not q:
		results = []
	else:
		qlike = f'%{q}%'
		results = db.execute('SELECT * FROM items WHERE title LIKE ? OR content LIKE ? ', (qlike, qlike)).fetchall()
	return render_template('search.html', q=q, results=results)


@app.route('/admin/users')
@admin_required
def admin_users():
	db = get_db()
	users = db.execute('SELECT id, username, is_admin FROM users').fetchall()
	return render_template('admin.html', users=users)


@app.route('/api/items')
def api_items():
	db = get_db()
	items = db.execute('SELECT id, title, content FROM items').fetchall()
	return jsonify([dict(ix) for ix in items])


if __name__ == '__main__':
	if not os.path.exists(DB_PATH):
		open(DB_PATH, 'a').close()
	with app.app_context():
		init_db()
		seed_db()
	app.run(host='0.0.0.0', port=5000, debug=True)

