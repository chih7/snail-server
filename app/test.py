#!flask/bin/python
from flask import Flask, jsonify
from flask import abort
from flask import make_response
from flask import request
from flask import url_for
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)

auth = HTTPBasicAuth()

@auth.get_password
def get_password(username):
    if username == 'ok':
        return 'python'
    return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)

users = [
    {
        'id': 1,
        'name': u'test',
        'passwd': u'test',
        'type': u'student'
    },
    {
        'id': 2,
        'name': u'test2',
        'passwd': u'test2',
        'type': u'student'
    }
]


@app.route('/snail/api/v0.1/users', methods=['GET'])
@auth.login_required
def get_users():
    return jsonify({'users': map(make_public_user, users)})


@app.route('/snail/api/v0.1/users/<int:user_id>', methods=['GET'])
@auth.login_required
def get_user(user_id):
    user = filter(lambda t: t['id'] == user_id, users)
    if len(user) == 0:
        abort(404)
    return jsonify({'user': user[0]})

@app.route('/snail/api/v0.1/users', methods=['POST'])
@auth.login_required
def create_user():
    if not request.json or not 'name' in request.json:
        abort(400)
    user = {
        'id': users[-1]['id'] + 1,
        'name': request.json['name'],
        'passwd': request.json['passwd'],
        'type': request.json['type']
    }
    users.append(user)
    return jsonify({'user': user}), 201

@app.errorhandler(404)
@auth.login_required
def not_found(error):
    return make_response(jsonify({'error': 'Not Found'}), 404)

@app.route('/snail/api/v0.1/users/<int:user_id>', methods=['PUT'])
@auth.login_required
def update_user(user_id):
    user = filter(lambda t: t['id'] == user_id, users)
    if len(user) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'name' in request.json and type(request.json['name']) != unicode:
        abort(400)
    if 'passwd' in request.json and type(request.json['passwd']) != unicode:
        abort(400)
    if 'type' in request.json and type(request.json['type']) != unicode:
        abort(400)
    user[0]['name'] = request.json.get('name', user[0]['name'])
    user[0]['passwd'] = request.json.get('passwd', user[0]['passwd'])
    user[0]['type'] = request.json.get('type', user[0]['type'])
    return jsonify({'user': user[0]})

@app.route('/snail/api/v0.1/users/<int:user_id>', methods=['DELETE'])
@auth.login_required
def delete_user(user_id):
    user = filter(lambda t: t['id'] == user_id, users)
    if len(user) == 0:
        abort(404)
    users.remove(user[0])
    return jsonify({'result': True})

def make_public_user(user):
    new_user = {}
    for field in user:
        if field == 'id':
            new_user['url'] = url_for('get_user', user_id=user['id'], _external=True)
        else:
            new_user[field] = user[field]
    return new_user


if __name__ == '__main__':
    app.run(debug=True)
