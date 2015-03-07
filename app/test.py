#!flask/bin/python

import os
import pymongo
import bson.binary
import bson.objectid
import bson.errors
import datetime
import hashlib
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import Response
from flask import abort
from flask import make_response
from flask import request
from flask import url_for
from flask import g
from cStringIO import StringIO
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from PIL import Image


# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'watchaaaaaadog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
auth = HTTPBasicAuth()
db = SQLAlchemy(app)

mongodb = pymongo.MongoClient('localhost', 27017).pic


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))
    # type = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user


def make_public_user(user):
    new_user = {}
    for field in user:
        if field == 'id':
            new_user['url'] = url_for('get_user', user_id=user['id'], _external=True)
        else:
            new_user[field] = user[field]
    return new_user


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not Found'}), 404)


@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify({'error': 'Bad Request'}), 400)


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# @app.route('/snail/api/v0.1/users', methods=['GET'])
# @auth.login_required
# def get_users():
# users = User.query.get()
#     return jsonify({'users': map(make_public_user, users)})


@app.route('/snail/api/v0.1/users/<int:user_id>', methods=['GET'])
@auth.login_required
def get_user(user_id):
    # user = filter(lambda t: t['id'] == user_id, users)
    user = User.query.get(user_id)
    if not user:
        abort(400)
    return jsonify({'id': user.id, 'username': user.username})


@app.route('/snail/api/v0.1/users', methods=['POST'])
@auth.login_required
def create_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:  # exsiting user
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    #return jsonify({'username': map(make_public_user, user)}), 201
    return jsonify({'id': user.id, 'username': user.username}), 201
    # {'Location': url_for('get_user', id = user.id, _external = True)}


# @app.route('/snail/api/v0.1/users/<int:user_id>', methods=['PUT'])
# @auth.login_required
# def update_user(user_id):
#     user = User.query.get(user_id)
#     if not user:
#         abort(404)
#     if not request.json:
#         abort(400)
#     if 'username' in request.json and type(request.json['namename']) != unicode:
#         abort(400)
#     if 'password' in request.json and type(request.json['password']) != unicode:
#         abort(400)
#     if 'type' in request.json and type(request.json['type']) != unicode:
#         abort(400)
#     user[0]['username'] = request.json.get('username', user[0]['username'])
#     user[0]['password'] = request.json.get('password', user[0]['password'])
#     user[0]['type'] = request.json.get('type', user[0]['type'])
#     return jsonify({'username': user[0]})

# @app.route('/snail/api/v0.1/users/<int:user_id>', methods=['DELETE'])
# @auth.login_required
# def delete_user(user_id):
#     if User.query.filter_by(id=user_id).first() is None:
#         abort(404)
#     user = User(id=user_id)
#     db.session.remove(user)
#     db.session.commit()
#     return jsonify({'result': True})


@app.route('/snail/api/v0.1/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/snail/api/v0.1/ok')
@auth.login_required
def get_resource():
    return jsonify({'isok': 'ok!'})


allow_formats = set(['jpeg', 'png', 'gif'])


def save_file(f):
    content = StringIO(f.read())
    try:
        mime = Image.open(content).format.lower()
        if mime not in allow_formats:
            raise IOError()
    except IOError:
        abort(400)

    sha1 = hashlib.sha1(content.getvalue()).hexdigest()
    c = dict(
        content=bson.binary.Binary(content.getvalue()),
        mime=mime,
        time=datetime.datetime.utcnow(),
        sha1=sha1,
    )
    try:
        mongodb.files.save(c)
    except pymongo.errors.DulicateKeyError:
        pass
    return sha1


@app.route('/snail/api/v0.1/pic/<sha1>')
@auth.login_required
def server_file(sha1):
    try:
        f = mongodb.files.find_one({'sha1': sha1})
        if f is None:
            raise bson.errors.InvalidId()
        if request.headers.get('If_Modified_Since') == f['time'].ctime():
            return Response(status=304)
        resp = Response(f['content'], mimetype='image/' + f['mime'])
        resp.headers['Last-Modified'] = f['time'].ctime()
        return resp
    except bson.errors.InvalidId:
        abort(404)


@app.route('/snail/api/v0.1/upload', methods=['POST'])
@auth.login_required
def upload():
    f = request.files['uploaded_file']
    sha1 = save_file(f)
    return jsonify({'sha1': sha1})


# @app.route('/')
# def index():
#     return '''
#     <!doctype html>
#     <html>
#     <body>
#     <form action='/snail/api/v0.1/upload' method='post' enctype='multipart/form-data'>
#          <input type='file' name='uploaded_file'>
#          <input type='submit' value='Upload'>
#     </form>
#     '''


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=80)
