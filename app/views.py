from flask import render_template, flash, redirect
from app import app
from forms import LoginForm

@app.route('/')
@app.route('/index')
def index():
    user = { 'nickname': 'Miguel' }#fake user
    posts = [
        {
            'author': {'nickname': 'John'},
            'body': 'ggggggggggg'
        },
        {
            'author': {'nickname': 'Susan'},
            'body': 'hhhhhhhhhhh'
        }
    ]
    return render_template("index.html",
            title = 'Home',
            user = user,
            posts = posts)

# index view function suppressed for brevity

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    return render_template('login.html',
        title = 'Sign In',
        form = form)

