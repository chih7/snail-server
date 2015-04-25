#!flask/bin/python
# -*- coding: utf-8 -*-

import os
import pymongo
import bson.binary
import bson.objectid
import bson.errors
import hashlib
from flask import Flask
from flask import jsonify
from flask import Response
from flask import abort
from flask import make_response
from flask import request
from flask import url_for
from flask import g
from datetime import datetime
from cStringIO import StringIO
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from PIL import Image
from werkzeug.contrib.fixers import ProxyFix

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'watchaaaaaadog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.wsgi_app = ProxyFix(app.wsgi_app)


# extensions
auth = HTTPBasicAuth()
db = SQLAlchemy(app)

mongodb = pymongo.MongoClient('localhost', 27017).pic


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column((db.String(64)), index=True)
    nickname = db.Column((db.String(64)))
    password_hash = db.Column((db.String(64)))
    type = db.Column((db.String(64)))
    sha1 = db.Column(db.String(256))
    about = db.Column(db.String(2048))

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


class Ques(db.Model):
    __tablename__ = 'ques'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column((db.String(64)))
    comp_id = db.Column((db.String(64)))
    user_id = db.Column(db.Integer)
    time = db.Column(db.DateTime, default=datetime.now())
    number = db.Column(db.Integer)
    title = db.Column((db.String(1024)))
    content = db.Column((db.String(2048)))
    sha1 = db.Column(db.String(256))


class Answer(db.Model):
    __tablename__ = 'answer'
    id = db.Column(db.Integer, primary_key=True)
    ques_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    time = db.Column(db.DateTime, default=datetime.now())
    number = db.Column(db.Integer)
    content = db.Column((db.String(4096)))
    sha1 = db.Column(db.String(256))


class Comp(db.Model):
    __tablename__ = 'comp'
    id = db.Column(db.Integer, primary_key=True)
    comp_type = db.Column((db.String(64)))
    name = db.Column((db.String(64)))


class Practice(db.Model):
    __tablename__ = 'practice'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column((db.String(1024)))
    office = db.Column(db.String(64))
    time = db.Column(db.DateTime, default=datetime.now())
    type = db.Column((db.String(64)))
    comp_id = db.Column((db.String(64)))
    comp_size = db.Column((db.String(64)))
    addr = db.Column((db.String(2048)))
    money = db.Column((db.String(1024)))
    ask = db.Column((db.String(4096)))
    duty = db.Column((db.String(4096)))


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


# ==============================================================================
# users


@app.route('/snail/api/v0.1/users', methods=['GET'])
@auth.login_required
def get_users():
    users = []
    db_users = User.query.all()

    for user in db_users:

        user_item = {
            'id': user.id,
            'username': user.username,
            'nickname': user.nickname,
            'type': user.type,
            'sha1': user.sha1,
            'about': user.about
        }
        users.append(user_item)
    return jsonify({'users': users})


@app.route('/snail/api/v0.1/users/<string:username>', methods=['GET'])
@auth.login_required
def get_user(username):
    # user = filter(lambda t: t['id'] == user_id, users)
    user = User.query.filter_by(username=username).first()
    if not user:
        abort(400)
    return jsonify({'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'type': user.type,
                    'sha1': user.sha1,
                    'about': user.about})


@app.route('/snail/api/v0.1/users', methods=['POST'])
#@auth.login_required
def create_user():
    username = request.json.get('username')
    nickname = request.json.get('nickname')
    password = request.json.get('password')
    type = request.json.get('type')
    sha1 = request.json.get('sha1')
    about = request.json.get('about')
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:  # exsiting user
        return jsonify({'error': 'exsiting user'}), 400
    user = User(username=username, nickname=nickname, type=type, sha1=sha1, about=about)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    # return jsonify({'username': map(make_public_user, user)}), 201
    return jsonify({'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'type': user.type,
                    'sha1': user.sha1,
                    'about': user.about}), 201
    # {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/snail/api/v0.1/users', methods=['PUT'])
@auth.login_required
def update_user():
    if not request.json:
        abort(400)
    username = request.json.get('username')
    nickname = request.json.get('nickname')
    password = request.json.get('password')
    type = request.json.get('type')
    sha1 = request.json.get('sha1')
    about = request.json.get('about')
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is None:  # not exsiting user
        abort(404)
    user = User.query.filter_by(username=username).first()
    user.nickname = nickname
    user.password_hash = pwd_context.encrypt(password)
    user.type = type
    user.sha1 = sha1
    user.about = about

    db.session.commit()
    # return jsonify({'username': map(make_public_user, user)}), 201
    return jsonify({'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'type': user.type,
                    'sha1': user.sha1,
                    'about': user.about}), 202
    # {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/snail/api/v0.1/users', methods=['DELETE'])
@auth.login_required
def delete_user():
    if not request.json:
        abort(400)
    username = request.json.get('username')
    if username is None:
        abort(400)
    if User.query.filter_by(username=username).first() is None:
        abort(404)
    user = User.query.filter_by(username=username).first()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'type': user.type,
                    'sha1': user.sha1,
                    'about': user.about,
                    'delete': 'OK'}), 202

@app.route('/snail/api/v0.1/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/snail/api/v0.1/ok')
@auth.login_required
def get_resource():
    return jsonify({'isok': 'ok!'})


#=======================================================================================
#ques


@app.route('/snail/api/v0.1/queses/<int:ques_id>', methods=['GET'])
@auth.login_required
def get_ques(ques_id):
    ques = Ques.query.get(ques_id)
    user = User.query.get(ques.user_id)
    comp = Comp.query.get(ques.comp_id)
    if not ques:
        abort(404)
    answer_num = Answer.query.filter_by(ques_id=ques_id).count()
    return jsonify({'id': ques.id,
                    'comp_id': ques.comp_id,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'user_id': ques.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(ques.time.strftime("%s")) * 1000,
                    'number': answer_num,
                    'title': ques.title,
                    'sha1': ques.sha1,
                    'content': ques.content})


@app.route('/snail/api/v0.1/queses', methods=['GET'])
@auth.login_required
def get_queses():
    queses = []
    db_queses = Ques.query.all()

    for ques in db_queses:
        user = User.query.get(ques.user_id)
        comp = Comp.query.get(ques.comp_id)
        answer_num = Answer.query.filter_by(ques_id=ques.id).count()
        ques_item = {
            'id': ques.id,
            'comp_id': ques.comp_id,
            'comp_name': comp.name,
            'comp_type': comp.comp_type,
            'user_id': ques.user_id,
            'user_name': user.username,
            'user_nickname': user.nickname,
            'user_pic': user.sha1,
            'user_type': user.type,
            'time': int(ques.time.strftime("%s")) * 1000,
            'number': answer_num,
            'title': ques.title,
            'sha1': ques.sha1,
            'content': ques.content
        }
        queses.append(ques_item)
    return jsonify({'queses': queses})


@app.route('/snail/api/v0.1/quesesofcomp_new', methods=['POST'])
@auth.login_required
def get_comp_queses_new():
    comp_id = request.json.get('comp_id')
    queses = []
    quesfilter = Ques.query.filter_by(comp_id=comp_id)

    for ques in quesfilter:
        user = User.query.get(ques.user_id)
        comp = Comp.query.get(ques.comp_id)
        answer_num = Answer.query.filter_by(ques_id=ques.id).count()
        ques_item = {
            'id': ques.id,
            'comp_id': ques.comp_id,
            'comp_name': comp.name,
            'comp_type': comp.comp_type,
            'user_id': ques.user_id,
            'user_name': user.username,
            'user_nickname': user.nickname,
            'user_pic': user.sha1,
            'user_type': user.type,
            'time': int(ques.time.strftime("%s")) * 1000,
            'number': answer_num,
            'title': ques.title,
            'sha1': ques.sha1,
            'content': ques.content
        }
        queses.append(ques_item)
    return jsonify({'queses': sorted(queses, key=lambda x: x['id'], reverse=True)})


@app.route('/snail/api/v0.1/quesesofcomp_hot', methods=['POST'])
@auth.login_required
def get_comp_queses_hot():
    comp_id = request.json.get('comp_id')
    queses = []
    quesfilter = Ques.query.filter_by(comp_id=comp_id)

    for ques in quesfilter:
        user = User.query.get(ques.user_id)
        comp = Comp.query.get(ques.comp_id)
        answer_num = Answer.query.filter_by(ques_id=ques.id).count()
        ques_item = {
            'id': ques.id,
            'comp_id': ques.comp_id,
            'comp_name': comp.name,
            'comp_type': comp.comp_type,
            'user_id': ques.user_id,
            'user_name': user.username,
            'user_nickname': user.nickname,
            'user_pic': user.sha1,
            'user_type': user.type,
            'time': int(ques.time.strftime("%s")) * 1000,
            'number': answer_num,
            'title': ques.title,
            'sha1': ques.sha1,
            'content': ques.content
        }
        queses.append(ques_item)
    return jsonify({'queses': sorted(queses, key=lambda x: x['number'])})


@app.route('/snail/api/v0.1/queses', methods=['POST'])
@auth.login_required
def create_ques():
    comp_id = request.json.get('comp_id')
    user_id = request.json.get('user_id')
    # number = request.json.get('number')
    title = request.json.get('title')
    sha1 = request.json.get('sha1')
    content = request.json.get('content')
    if title is None or type is None:
        abort(400)
    if Comp.query.filter_by(id=comp_id).first() is None \
            or User.query.filter_by(id=user_id).first() is None:
        abort(400)

    ques = Ques(comp_id=comp_id,
                time=datetime.now(),
                user_id=user_id,
                number=0,
                title=title,
                sha1=sha1,
                content=content)

    db.session.add(ques)
    db.session.commit()
    user = User.query.get(ques.user_id)
    comp = Comp.query.get(ques.comp_id)
    return jsonify({'id': ques.id,
                    'comp_id': ques.comp_id,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'user_id': ques.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(ques.time.strftime("%s")) * 1000,
                    'number': 0,
                    'title': ques.title,
                    'sha1': ques.sha1,
                    'content': ques.content})

@app.route('/snail/api/v0.1/queses', methods=['PUT'])
@auth.login_required
def update_ques():
    if not request.json:
        abort(400)
    ques_id = request.json.get('ques_id')
    comp_id = request.json.get('comp_id')
    user_id = request.json.get('user_id')
    title = request.json.get('title')
    sha1 = request.json.get('sha1')
    content = request.json.get('content')
    if ques_id is None:
        abort(400)
    if Ques.query.get(ques_id) is None:
        abort(404)

    ques = Ques.query.get(ques_id)
    ques.comp_id = comp_id
    ques.user_id = user_id
    ques.title = title
    ques.sha1 = sha1
    ques.content = content

    db.session.commit()
    user = User.query.get(ques.user_id)
    comp = Comp.query.get(ques.comp_id)
    answer_num = Answer.query.filter_by(ques_id=ques.id).count()
    return jsonify({'id': ques.id,
                    'comp_id': ques.comp_id,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'user_id': ques.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(ques.time.strftime("%s")) * 1000,
                    'number': answer_num,
                    'title': ques.title,
                    'sha1': ques.sha1,
                    'content': ques.content}), 202

@app.route('/snail/api/v0.1/queses', methods=['DELETE'])
@auth.login_required
def delete_ques():
    if not request.json:
        abort(400)
    ques_id = request.json.get('ques_id')
    if ques_id is None:
        abort(400)
    if Ques.query.get(ques_id) is None:
        abort(404)
    ques = Ques.query.get(ques_id)
    db.session.delete(ques)
    db.session.commit()
    user = User.query.get(ques.user_id)
    comp = Comp.query.get(ques.comp_id)
    answer_num = Answer.query.filter_by(ques_id=ques.id).count()
    return jsonify({'id': ques.id,
                    'comp_id': ques.comp_id,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'user_id': ques.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(ques.time.strftime("%s")) * 1000,
                    'number': answer_num,
                    'title': ques.title,
                    'sha1': ques.sha1,
                    'content': ques.content,
                    'delete': 'OK'}), 202

#=======================================================================================
#answer


@app.route('/snail/api/v0.1/answers/<int:answer_id>', methods=['GET'])
@auth.login_required
def get_answer(answer_id):
    answer = Answer.query.get(answer_id)
    user = User.query.get(answer.user_id)
    ques = Ques.query.get(answer.ques_id)
    if not answer:
        abort(404)
    return jsonify({'id': answer.id,
                    'ques_id': answer.ques_id,
                    'ques_type': ques.type,
                    'ques_comp_id': ques.comp_id,
                    'ques_number': ques.number,
                    'ques_title': ques.title,
                    'ques_time': ques.time,
                    'ques_user_id': ques.user_id,
                    'user_id': answer.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(answer.time.strftime("%s")) * 1000,
                    'number': answer.number,
                    'sha1': answer.sha1,
                    'content': answer.content})


@app.route('/snail/api/v0.1/answers', methods=['GET'])
@auth.login_required
def get_answers():
    db_answers = Answer.query.all()
    answers = []
    for answer in db_answers:
        user = User.query.get(answer.user_id)
        ques = Ques.query.get(answer.ques_id)
        answer_item = {
            'id': answer.id,
            'ques_id': answer.ques_id,
            'ques_type': ques.type,
            'ques_comp_id': ques.comp_id,
            'ques_number': ques.number,
            'ques_title': ques.title,
            'ques_time': ques.time,
            'ques_user_id': ques.user_id,
            'user_id': answer.user_id,
            'user_name': user.username,
            'user_nickname': user.nickname,
            'user_pic': user.sha1,
            'user_type': user.type,
            'time': int(answer.time.strftime("%s")) * 1000,
            'number': answer.number,
            'sha1': answer.sha1,
            'content': answer.content
        }
        answers.append(answer_item)
    return jsonify({'answers': answers})


@app.route('/snail/api/v0.1/answersofques_new', methods=['POST'])
@auth.login_required
def get_ques_answers_new():
    ques_id = request.json.get('ques_id')
    answers = []
    answersfilter = Answer.query.filter_by(ques_id=ques_id)
    for answer in answersfilter:
        user = User.query.get(answer.user_id)
        ques = Ques.query.get(answer.ques_id)
        answer_item = {
            'id': answer.id,
            'ques_id': answer.ques_id,
            'ques_type': ques.type,
            'ques_comp_id': ques.comp_id,
            'ques_number': ques.number,
            'ques_title': ques.title,
            'ques_time': ques.time,
            'ques_user_id': ques.user_id,
            'user_id': answer.user_id,
            'user_name': user.username,
            'user_nickname': user.nickname,
            'user_pic': user.sha1,
            'user_type': user.type,
            'time': int(answer.time.strftime("%s")) * 1000,
            'number': answer.number,
            'sha1': answer.sha1,
            'content': answer.content
        }
        answers.append(answer_item)
    return jsonify({'answers': sorted(answers, key=lambda x: x['id'],  reverse=True)})


@app.route('/snail/api/v0.1/answersofques_hot', methods=['POST'])
@auth.login_required
def get_ques_answers_hot():
    ques_id = request.json.get('ques_id')
    answers = []
    answersfilter = Answer.query.filter_by(ques_id=ques_id)
    for answer in answersfilter:
        user = User.query.get(answer.user_id)
        ques = Ques.query.get(answer.ques_id)
        answer_item = {
            'id': answer.id,
            'ques_id': answer.ques_id,
            'ques_type': ques.type,
            'ques_comp_id': ques.comp_id,
            'ques_number': ques.number,
            'ques_title': ques.title,
            'ques_time': ques.time,
            'ques_user_id': ques.user_id,
            'user_id': answer.user_id,
            'user_name': user.username,
            'user_nickname': user.nickname,
            'user_pic': user.sha1,
            'user_type': user.type,
            'time': int(answer.time.strftime("%s")) * 1000,
            'number': answer.number,
            'sha1': answer.sha1,
            'content': answer.content
        }
        answers.append(answer_item)
    return jsonify({'answers': sorted(answers, key=lambda x: x['number'])})


@app.route('/snail/api/v0.1/answers', methods=['POST'])
@auth.login_required
def create_answer():
    ques_id = request.json.get('ques_id')
    user_id = request.json.get('user_id')
    number = request.json.get('number')
    content = request.json.get('content')
    sha1 = request.json.get('sha1')
    if number is None:
        abort(400)
    if Ques.query.filter_by(id=ques_id).first() is None \
            or User.query.filter_by(id=user_id).first() is None:
        abort(400)
    answer = Answer(ques_id=ques_id,
                    time=datetime.now(),
                    user_id=user_id,
                    number=number,
                    sha1=sha1,
                    content=content)
    db.session.add(answer)
    db.session.commit()
    user = User.query.get(answer.user_id)
    ques = Ques.query.get(answer.ques_id)
    return jsonify({'id': answer.id,
                    'ques_id': answer.ques_id,
                    'ques_type': ques.type,
                    'ques_comp_id': ques.comp_id,
                    'ques_number': ques.number,
                    'ques_title': ques.title,
                    'ques_time': ques.time,
                    'ques_user_id': ques.user_id,
                    'user_id': answer.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(answer.time.strftime("%s")) * 1000,
                    'number': answer.number,
                    'sha1': answer.sha1,
                    'content': answer.content})

@app.route('/snail/api/v0.1/answers', methods=['PUT'])
@auth.login_required
def update_answer():
    if not request.json:
        abort(400)
    answer_id = request.json.get('answer_id')
    ques_id = request.json.get('ques_id')
    user_id = request.json.get('user_id')
    number = request.json.get('number')
    content = request.json.get('content')
    sha1 = request.json.get('sha1')
    if answer_id is None:
        abort(400)
    if Answer.query.get(answer_id) is None:
        abort(404)
    answer = Answer.query.get(answer_id)
    answer.ques_id = ques_id
    answer.user_id = user_id
    answer.number = number
    answer.content = content
    answer.sha1 = sha1
    db.session.commit()
    user = User.query.get(answer.user_id)
    ques = Ques.query.get(answer.ques_id)
    return jsonify({'id': answer.id,
                    'ques_id': answer.ques_id,
                    'ques_type': ques.type,
                    'ques_comp_id': ques.comp_id,
                    'ques_number': ques.number,
                    'ques_title': ques.title,
                    'ques_time': ques.time,
                    'ques_user_id': ques.user_id,
                    'user_id': answer.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(answer.time.strftime("%s")) * 1000,
                    'number': answer.number,
                    'sha1': answer.sha1,
                    'content': answer.content}), 202


@app.route('/snail/api/v0.1/answers', methods=['DELETE'])
@auth.login_required
def delete_answer():
    if not request.json:
        abort(400)
    answer_id = request.json.get('answer_id')
    if answer_id is None:
        abort(400)
    if Answer.query.get(answer_id) is None:
        abort(404)
    answer = Answer.query.get(answer_id)
    db.session.delete(answer)
    db.session.commit()
    user = User.query.get(answer.user_id)
    ques = Ques.query.get(answer.ques_id)
    return jsonify({'id': answer.id,
                    'ques_id': answer.ques_id,
                    'ques_type': ques.type,
                    'ques_comp_id': ques.comp_id,
                    'ques_number': ques.number,
                    'ques_title': ques.title,
                    'ques_time': ques.time,
                    'ques_user_id': ques.user_id,
                    'user_id': answer.user_id,
                    'user_name': user.username,
                    'user_nickname': user.nickname,
                    'user_pic': user.sha1,
                    'user_type': user.type,
                    'time': int(answer.time.strftime("%s")) * 1000,
                    'number': answer.number,
                    'sha1': answer.sha1,
                    'content': answer.content,
                    'delete': 'OK'}), 202


#=========================================================================================================
#comp


@app.route('/snail/api/v0.1/comps/<int:comp_id>', methods=['GET'])
@auth.login_required
def get_comp(comp_id):
    comp = Comp.query.get(comp_id)
    if not comp:
        abort(404)
    return jsonify({'id': comp.id, 'type': comp.comp_type, 'name': comp.name})


@app.route('/snail/api/v0.1/comps', methods=['GET'])
@auth.login_required
def get_comps():
    db_comps = Comp.query.all()
    comps = []
    for comp in db_comps:
        comp_item = {
            'id': comp.id,
            'type': comp.comp_type,
            'name': comp.name
        }
        comps.append(comp_item)
    return jsonify({'comps': comps})


@app.route('/snail/api/v0.1/comps', methods=['POST'])
@auth.login_required
def create_comps():
    comp_type = request.json.get('type')
    name = request.json.get('name')
    if comp_type is None or name is None:
        abort(400)
    comp = Comp(comp_type=comp_type, name=name)
    db.session.add(comp)
    db.session.commit()
    return jsonify({'id': comp.id, 'type': comp.comp_type, 'name': comp.name}), 201

@app.route('/snail/api/v0.1/comps', methods=['PUT'])
@auth.login_required
def update_comp():
    if not request.json:
        abort(400)
    comp_id = request.json.get('comp_id')
    comp_type = request.json.get('type')
    name = request.json.get('name')
    if comp_id is None:
        abort(400)
    if Comp.query.get(comp_id) is None:
        abort(400)
    comp = Comp.query.get(comp_id)
    comp.comp_type = comp_type
    comp.name = name
    db.session.commit()
    return jsonify({'id': comp.id, 'type': comp.comp_type, 'name': comp.name}), 202

@app.route('/snail/api/v0.1/comps', methods=['DELETE'])
@auth.login_required
def delete_comp():
    if not request.json:
        abort(400)
    comp_id = request.json.get('comp_id')
    if comp_id is None:
        abort(400)
    if Comp.query.get(comp_id) is None:
        abort(404)
    comp = Comp.query.get(comp_id)
    db.session.delete(comp)
    return jsonify({'id': comp.id, 'type': comp.comp_type, 'name': comp.name, 'delete': 'OK'}), 202


#=======================================================================================
#Practice


@app.route('/snail/api/v0.1/practice/<int:practice_id>', methods=['GET'])
@auth.login_required
def get_practice(practice_id):
    practice = Practice.query.get(practice_id)
    comp = Comp.query.get(practice.comp_id)
    if not practice:
        abort(404)
    return jsonify({'id': practice.id,
                    'title': practice.title,
                    'office': practice.office,
                    'time': int(practice.time.strftime("%s")) * 1000,
                    'type': practice.type,
                    'comp_id': practice.comp_id,
                    'comp_size': practice.comp_size,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'addr': practice.addr,
                    'money': practice.money,
                    'ask': practice.ask,
                    'duty': practice.duty})


@app.route('/snail/api/v0.1/practices', methods=['GET'])
@auth.login_required
def get_practices():
    db_practices = Practice.query.all()
    practices = []

    for practice in db_practices:
        comp = Comp.query.get(practice.comp_id)
        practice_item = {
            'id': practice.id,
            'title': practice.title,
            'office': practice.office,
            'time': int(practice.time.strftime("%s")) * 1000,
            'type': practice.type,
            'comp_id': practice.comp_id,
            'comp_size': practice.comp_size,
            'comp_name': comp.name,
            'comp_type': comp.comp_type,
            'addr': practice.addr,
            'money': practice.money,
            'ask': practice.ask,
            'duty': practice.duty
        }
        practices.append(practice_item)
    return jsonify({'practices': practices})


@app.route('/snail/api/v0.1/practicesofcomp', methods=['POST'])
@auth.login_required
def get_ques_practices():
    comp_id = request.json.get('comp_id')
    practices = []
    practicesfilter = Practice.query.filter_by(comp_id=comp_id)
    for practice in practicesfilter:
        comp = Comp.query.get(practice.comp_id)
        practice_item = {
            'id': practice.id,
            'title': practice.title,
            'office': practice.office,
            'time': int(practice.time.strftime("%s")) * 1000,
            'type': practice.type,
            'comp_id': practice.comp_id,
            'comp_size': practice.comp_size,
            'comp_name': comp.name,
            'comp_type': comp.comp_type,
            'addr': practice.addr,
            'money': practice.money,
            'ask': practice.ask,
            'duty': practice.duty
        }
        practices.append(practice_item)
    return jsonify({'practices': practices})
    # return jsonify({'num': practices_num})


@app.route('/snail/api/v0.1/practices', methods=['POST'])
@auth.login_required
def create_practice():
    title = request.json.get('title')
    office = request.json.get('office')
    type = request.json.get('type')
    comp_id = request.json.get('comp_id')
    comp_size = request.json.get('comp_size')
    addr = request.json.get('addr')
    ask = request.json.get('ask')
    money = request.json.get('money')
    duty = request.json.get('duty')
    if title is None or office is None or ask is None or duty is None:
        abort(400)
    if Comp.query.filter_by(id=comp_id).first() is None:
        abort(400)
    practice = Practice(title=title,
                        time=datetime.now(),
                        office=office,
                        type=type,
                        comp_id=comp_id,
                        comp_size=comp_size,
                        addr=addr,
                        ask=ask,
                        money=money,
                        duty=duty)
    db.session.add(practice)
    db.session.commit()
    comp = Comp.query.get(practice.comp_id)
    return jsonify({'id': practice.id,
                    'title': practice.title,
                    'office': practice.office,
                    'time': int(practice.time.strftime("%s")) * 1000,
                    'type': practice.type,
                    'comp_id': practice.comp_id,
                    'comp_size': practice.comp_size,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'addr': practice.addr,
                    'money': practice.money,
                    'ask': practice.ask,
                    'duty': practice.duty})

@app.route('/snail/api/v0.1/practices', methods=['PUT'])
@auth.login_required
def update_practice():
    if not request.json:
        abort(400)
    practice_id = request.json.get('practice_id')
    title = request.json.get('title')
    office = request.json.get('office')
    type = request.json.get('type')
    comp_id = request.json.get('comp_id')
    comp_size = request.json.get('comp_size')
    addr = request.json.get('addr')
    ask = request.json.get('ask')
    money = request.json.get('money')
    duty = request.json.get('duty')
    if practice_id is None:
        abort(400)
    if Practice.query.get(practice_id) is None:
        abort(404)
    practice = Practice.query.get(practice_id)
    practice.title = title
    practice.office = office
    practice.type = type
    practice.comp_id = comp_id
    practice.comp_size =comp_size
    practice.addr = addr
    practice.ask = ask
    practice.money = money
    practice.duty =duty
    db.session.commit()
    comp = Comp.query.get(practice.comp_id)
    return jsonify({'id': practice.id,
                    'title': practice.title,
                    'office': practice.office,
                    'time': int(practice.time.strftime("%s")) * 1000,
                    'type': practice.type,
                    'comp_id': practice.comp_id,
                    'comp_size': practice.comp_size,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'addr': practice.addr,
                    'money': practice.money,
                    'ask': practice.ask,
                    'duty': practice.duty}), 202

@app.route('/snail/api/v0.1/practices', methods=['DELETE'])
@auth.login_required
def delete_practice():
    if not request.json:
        abort(400)
    practice_id = request.json.get('practice_id')
    if practice_id is None:
        abort(400)
    if Practice.query.get(practice_id) is None:
        abort(404)
    practice = Practice.query.get(practice_id)
    db.session.delete(practice)
    db.session.commit()
    comp = Comp.query.get(practice.comp_id)
    return jsonify({'id': practice.id,
                    'title': practice.title,
                    'office': practice.office,
                    'time': int(practice.time.strftime("%s")) * 1000,
                    'type': practice.type,
                    'comp_id': practice.comp_id,
                    'comp_size': practice.comp_size,
                    'comp_name': comp.name,
                    'comp_type': comp.comp_type,
                    'addr': practice.addr,
                    'money': practice.money,
                    'ask': practice.ask,
                    'duty': practice.duty,
                    'delete': 'OK'}), 202


#============================================================================================
#pic


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
        time=datetime.utcnow(),
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


@app.route('/')
def index():
    return '''
    <!doctype html>
    <html>
    <body>
    <form action='/snail/api/v0.1/upload' method='post' enctype='multipart/form-data'>
         <input type='file' name='uploaded_file'>
         <input type='submit' value='Upload'>
    </form>
    '''


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True, port=8000)
