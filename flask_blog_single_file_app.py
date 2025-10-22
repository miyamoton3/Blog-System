# flask_blog_single_file_app.py
from flask import Flask, g, render_template_string, request, redirect, url_for, session, flash, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

DATABASE = os.path.join(os.path.dirname(__file__), 'blog.db')
SECRET_KEY = 'replace-this-with-a-secure-random-string'

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# ----- DB helpers -----
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS User (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS Article (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        author_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT,
        FOREIGN KEY(author_id) REFERENCES User(id)
    );
    CREATE TABLE IF NOT EXISTS Comment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        article_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(article_id) REFERENCES Article(id),
        FOREIGN KEY(author_id) REFERENCES User(id)
    );
    """)
    db.commit()

# ----- auth helpers -----
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    db = get_db()
    return db.execute('SELECT id, username, email, created_at FROM User WHERE id = ?', (uid,)).fetchone()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash('ログインが必要です。')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return wrapper

# ----- templates (render_template_string で単一ファイル完結に) -----
base_tpl = """
<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Mini Blog</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light mb-4">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('index') }}">Mini Blog</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
        {% if user %}
          <li class="nav-item"><a class="nav-link" href="#">ようこそ {{ user['username'] }}</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('new_article') }}">投稿</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">ログアウト</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">ログイン</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">登録</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>

<div class="container">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info">
        {% for m in messages %} <div>{{ m }}</div> {% endfor %}
      </div>
    {% endif %}
  {% endwith %}
  {{ body|safe }}
</div>
</body>
</html>
"""

# ----- routes -----
@app.route('/')
def index():
    db = get_db()
    articles = db.execute('''
        SELECT Article.*, User.username FROM Article
        JOIN User ON Article.author_id = User.id
        ORDER BY created_at DESC
    ''').fetchall()
    body = render_template_string("""
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h1>記事一覧</h1>
      {% if user %}
        <a class="btn btn-primary" href="{{ url_for('new_article') }}">新規作成</a>
      {% endif %}
    </div>
    {% for a in articles %}
      <div class="card mb-3">
        <div class="card-body">
          <h4><a href="{{ url_for('article_detail', article_id=a['id']) }}">{{ a['title'] }}</a></h4>
          <p class="text-muted">投稿者: {{ a['username'] }} | 投稿日: {{ a['created_at'] }}</p>
          <p>{{ a['body'][:200] }}{% if a['body']|length > 200 %}...{% endif %}</p>
          {% if user and user['id'] == a['author_id'] %}
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('edit_article', article_id=a['id']) }}">編集</a>
          {% endif %}
        </div>
      </div>
    {% else %}
      <p>まだ記事がありません。</p>
    {% endfor %}
    """, articles=articles, user=current_user())
    return render_template_string(base_tpl, body=body, user=current_user())

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip()
        password = request.form.get('password','')
        if not username or not email or not password:
            flash('すべて入力してください。')
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute('INSERT INTO User (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
                       (username, email, generate_password_hash(password), datetime.utcnow().isoformat()))
            db.commit()
            flash('登録が完了しました。ログインしてください。')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('ユーザ名またはメールアドレスが既に使われています。')
            return redirect(url_for('register'))
    body = render_template_string("""
    <h1>ユーザ登録</h1>
    <form method="post">
      <div class="mb-3"><input class="form-control" name="username" placeholder="ユーザ名"></div>
      <div class="mb-3"><input class="form-control" name="email" placeholder="メールアドレス" type="email"></div>
      <div class="mb-3"><input class="form-control" name="password" placeholder="パスワード" type="password"></div>
      <button class="btn btn-primary">登録</button>
    </form>
    """)
    return render_template_string(base_tpl, body=body, user=current_user())

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip()
        password = request.form.get('password','')
        db = get_db()
        user = db.execute('SELECT * FROM User WHERE email = ?', (email,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('ログインしました。')
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)
        else:
            flash('メールアドレスかパスワードが正しくありません。')
            return redirect(url_for('login'))
    body = render_template_string("""
    <h1>ログイン</h1>
    <form method="post">
      <div class="mb-3"><input class="form-control" name="email" placeholder="メールアドレス" type="email"></div>
      <div class="mb-3"><input class="form-control" name="password" placeholder="パスワード" type="password"></div>
      <button class="btn btn-primary">ログイン</button>
    </form>
    """)
    return render_template_string(base_tpl, body=body, user=current_user())

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('ログアウトしました。')
    return redirect(url_for('index'))

@app.route('/article/new', methods=['GET','POST'])
@login_required
def new_article():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        body_text = request.form.get('body','').strip()
        if not title or not body_text:
            flash('タイトルと本文は必須です。')
            return redirect(url_for('new_article'))
        db = get_db()
        user = current_user()
        db.execute('INSERT INTO Article (title, body, author_id, created_at) VALUES (?, ?, ?, ?)',
                   (title, body_text, user['id'], datetime.utcnow().isoformat()))
        db.commit()
        flash('記事を投稿しました。')
        return redirect(url_for('index'))
    body = render_template_string("""
    <h1>新規記事</h1>
    <form method="post">
      <div class="mb-3"><input class="form-control" name="title" placeholder="タイトル"></div>
      <div class="mb-3"><textarea class="form-control" name="body" rows="8" placeholder="本文"></textarea></div>
      <button class="btn btn-primary">投稿</button>
    </form>
    """)
    return render_template_string(base_tpl, body=body, user=current_user())

@app.route('/article/<int:article_id>')
def article_detail(article_id):
    db = get_db()
    article = db.execute('''
        SELECT Article.*, User.username FROM Article
        JOIN User ON Article.author_id = User.id
        WHERE Article.id = ?
    ''', (article_id,)).fetchone()
    if not article:
        abort(404)
    comments = db.execute('''
        SELECT Comment.*, User.username FROM Comment
        JOIN User ON Comment.author_id = User.id
        WHERE Comment.article_id = ?
        ORDER BY created_at ASC
    ''', (article_id,)).fetchall()
    body = render_template_string("""
    <h1>{{ article['title'] }}</h1>
    <p class="text-muted">投稿者: {{ article['username'] }} | 投稿日: {{ article['created_at'] }}</p>
    <div class="mb-4"><pre style="white-space: pre-wrap;">{{ article['body'] }}</pre></div>

    {% if user and user['id'] == article['author_id'] %}
      <p><a class="btn btn-sm btn-outline-secondary" href="{{ url_for('edit_article', article_id=article['id']) }}">編集</a></p>
    {% endif %}

    <hr>
    <h4>コメント</h4>
    {% for c in comments %}
      <div class="mb-2">
        <strong>{{ c['username'] }}</strong> <small class="text-muted">{{ c['created_at'] }}</small>
        <div>{{ c['body'] }}</div>
      </div>
    {% else %}
      <p>まだコメントはありません。</p>
    {% endfor %}

    {% if user %}
      <hr>
      <form method="post" action="{{ url_for('add_comment', article_id=article['id']) }}">
        <div class="mb-3"><textarea class="form-control" name="body" rows="3" placeholder="コメント"></textarea></div>
        <button class="btn btn-primary">コメント投稿</button>
      </form>
    {% else %}
      <p><a href="{{ url_for('login') }}">ログイン</a>するとコメントできます。</p>
    {% endif %}
    """, article=article, comments=comments, user=current_user())
    return render_template_string(base_tpl, body=body, user=current_user())

@app.route('/article/<int:article_id>/comment', methods=['POST'])
@login_required
def add_comment(article_id):
    body_text = request.form.get('body','').strip()
    if not body_text:
        flash('コメントを入力してください。')
        return redirect(url_for('article_detail', article_id=article_id))
    db = get_db()
    user = current_user()
    # 簡単な存在チェック
    a = db.execute('SELECT id FROM Article WHERE id = ?', (article_id,)).fetchone()
    if not a:
        abort(404)
    db.execute('INSERT INTO Comment (article_id, author_id, body, created_at) VALUES (?, ?, ?, ?)',
               (article_id, user['id'], body_text, datetime.utcnow().isoformat()))
    db.commit()
    flash('コメントを投稿しました。')
    return redirect(url_for('article_detail', article_id=article_id))

@app.route('/article/<int:article_id>/edit', methods=['GET','POST'])
@login_required
def edit_article(article_id):
    db = get_db()
    article = db.execute('SELECT * FROM Article WHERE id = ?', (article_id,)).fetchone()
    if not article:
        abort(404)
    user = current_user()
    if user['id'] != article['author_id']:
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        body_text = request.form.get('body','').strip()
        if not title or not body_text:
            flash('タイトルと本文は必須です。')
            return redirect(url_for('edit_article', article_id=article_id))
        db.execute('UPDATE Article SET title = ?, body = ?, updated_at = ? WHERE id = ?',
                   (title, body_text, datetime.utcnow().isoformat(), article_id))
        db.commit()
        flash('記事を更新しました。')
        return redirect(url_for('article_detail', article_id=article_id))
    body = render_template_string("""
    <h1>記事編集</h1>
    <form method="post">
      <div class="mb-3"><input class="form-control" name="title" value="{{ article['title'] }}"></div>
      <div class="mb-3"><textarea class="form-control" name="body" rows="8">{{ article['body'] }}</textarea></div>
      <button class="btn btn-primary">更新</button>
      <a class="btn btn-secondary" href="{{ url_for('article_detail', article_id=article['id']) }}">キャンセル</a>
    </form>
    """, article=article)
    return render_template_string(base_tpl, body=body, user=current_user())

# ----- app start -----
if __name__ == '__main__':
    # ensure DB exists and tables created
    with app.app_context():
        init_db()
    app.run(debug=True)
