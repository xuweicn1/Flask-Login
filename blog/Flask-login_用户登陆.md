# Flask-Login

[![build status](https://secure.travis-ci.org/maxcountryman/flask-login.png?branch=master)](https://travis-ci.org/#!/maxcountryman/flask-login)

Flask-Login 提供用户会话管理，处理常见的登录、退出和注册的任务。

Flask-Login 没有绑定数据库,可以从数据库回调用户对象。

## 安装flask-login

```sh
pip install flask-login
```

## 结构

```sh
|-- app/
|   |-- __init__.py
|   |-- forms.py
|   |-- models.py
|   |-- routes.py
|   `-- templates/
|       |-- base.html
|       |-- index.html
|       |-- login.html
|       `-- register.html
|-- app.db
|-- config.py
`-- microblog.py
```

## 环境变量

安装`python-dotenv`，避免了每次运行代码都要定义环境变量

```sh
pip install python-dotenv
```

根目录新建`.flaskenv`环境变量文件
`.flaskenv`：

```sh
FLASK_APP=microblog.py
```

`microblog.py`:

```python
from app import app, db
from app.models import User, Post


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Post': Post}

```

## 配置项

```python
import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
```

`app.dp`项目运行后产生

## 项目运行

到项目根目录

```sh
PS D:\Days\Flask-Login> flask run
 * Serving Flask-SocketIO app "microblog.py"
 * Forcing debug mode off
 * Serving Flask app "microblog.py"
 * Environment: production
   WARNING: Do not use the development server in a production environment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
127.0.0.1 - - [30/Nov/2018 11:22:44] "[37mGET /login?next=%2F HTTP/1.1[0m" 200 -
```

## 定义初始化模块

`app/__init__.py`

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config
from flask_login import LoginManager

app = Flask(__name__)

# 定义配置
app.config.from_object(Config)

# 定义数据库
db = SQLAlchemy(app)

# 数据库迁移
migrate = Migrate(app, db)

# Flask-Login初始化
login = LoginManager(app)
    
# login 是视图函数名称
# 游客如果访问其他页面将跳转到登陆界面
login.login_view = 'login'

from app import routes, models
```

## 用户加载模块

用户加载模块,完成如下2个功能：

1. 定义用户数据库模型
2. 加载数据库匹配用户

注意事项：

使用Flask-Login的user类必须实现下列属性方法：

| 方法             | 含义                                                         |
| ---------------- | ------------------------------------------------------------ |
| is_authenticated | 是登陆用户，返回TRUE；否则False                              |
| is_active        | 是活动用户，返回TRUE；否则False                              |
| is_anonymous     | 是匿名用户，返回TRUE；否则False                              |
| get_id()         | 返回用户唯一标识，用unicode编码，即使是数字类型也要转换成unicode |

如果继承`UserMixin`类，则默认实现了上述方法；

`app/models.py`

```python
from datetime import datetime
from app import db, login

# 密码哈希和验证
from werkzeug.security import generate_password_hash, check_password_hash

# UserMixin类实现绝大部分的用户模型
from flask_login import UserMixin

# 1、定义用户数据库模型
# FUserMixin：用来定义用户状态
# db.Model 数据库基类
# 密码哈希验证

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    #将‘password’ 变成散列密码
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    #将‘password’ 变成散列密码和self.password_hash对比，相同返回True，不同返回False
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)



#2 、加载数据库匹配用户
# @login.user_loader回调函数
# 向Flask-Login注册用户加载程序，传递的参数是字符串
# 在数据库中用用户标识符查找
# 如果能找到返回用户对象，否则 返回None。
@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)
```

## 路由和视图函数

- 用户登陆
- 用户注销
- 用户注册

`app/routes.py`

```python
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app import app, db
from app.forms import LoginForm, RegistrationForm
from app.models import User

# 起始页
@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = [
        {
            'author': {'username': 'John'},
            'body': 'Beautiful day in Portland!'
        },
        {
            'author': {'username': 'Susan'},
            'body': 'The Avengers movie was so cool!'
        }
    ]
    return render_template('index.html', title='Home', posts=posts)

# 登陆用户
@app.route('/login', methods=['GET', 'POST'])
def login():
    #如果是登陆用户，跳转到'index'
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    #调用LoginForm类
    form = LoginForm()
    if form.validate_on_submit():
        #query.filter_by() 把等值过滤器添加到原查询上,此处提出填入user值
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

# 注销用户
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# 用户注册
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
```

## 表单

实现2个功能：

- 登陆验证
- 用户注册

 `app/forms.py`：

```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User

# 用户登陆
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

# 用户注册
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
```

## 模板

`app/templates/base.html`：基本模板，用于做父类提供继承

```python
<html>
    <head>
        {% if title %}
        <title>{{ title }} - Microblog</title>
        {% else %}
        <title>Welcome to Microblog</title>
        {% endif %}
    </head>
    <body>
        <div>
            Microblog:
            <a href="{{ url_for('index') }}">Home</a>
            {% if current_user.is_anonymous %}
            <a href="{{ url_for('login') }}">Login</a>
            {% else %}
            <a href="{{ url_for('logout') }}">Logout</a>
            {% endif %}
        </div>
        <hr>
        {% with messages = get_flashed_messages() %}
        {% if messages %}
        <ul>
            {% for message in messages %}
            <li>{{ message }}</li>
            {% endfor %}
        </ul>
        {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </body>
</html>
```

`app/templates/index.html`：起始页面

```html
{% extends "base.html" %}

{% block content %}
    <h1>Hi, {{ current_user.username }}!</h1>
    {% for post in posts %}
    <div><p>{{ post.author.username }} says: <b>{{ post.body }}</b></p></div>
    {% endfor %}
{% endblock %}
```

`app/templates/register.html`：注册用户模板

```html
{% extends "base.html" %}

{% block content %}
    <h1>Register</h1>
    <form action="" method="post">
        {{ form.hidden_tag() }}
        <p>
            {{ form.username.label }}<br>
            {{ form.username(size=32) }}<br>
            {% for error in form.username.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.email.label }}<br>
            {{ form.email(size=64) }}<br>
            {% for error in form.email.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.password.label }}<br>
            {{ form.password(size=32) }}<br>
            {% for error in form.password.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.password2.label }}<br>
            {{ form.password2(size=32) }}<br>
            {% for error in form.password2.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>{{ form.submit() }}</p>
    </form>
{% endblock %}
```

`app/templates/login.html`：未注册用户链接到登陆页面

```html
{% extends "base.html" %}

{% block content %}
    <h1>Sign In</h1>
    <form action="" method="post" novalidate>
        {{ form.hidden_tag() }}
        <p>
            {{ form.username.label }}<br>
            {{ form.username(size=32) }}<br>
            {% for error in form.username.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.password.label }}<br>
            {{ form.password(size=32) }}<br>
            {% for error in form.password.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>{{ form.remember_me() }} {{ form.remember_me.label }}</p>
        <p>{{ form.submit() }}</p>
    </form>

    <p>New User? <a href="{{ url_for('register') }}">Click to Register!</a></p>
{% endblock %}
```
