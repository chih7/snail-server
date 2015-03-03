#!flask/bin/python
from flask import Flask,jsonify
from flask import abort

app = Flask(__name__)

users = [
        {
            'id':1,
            'name':u'test',
            'passwd':u'test',
            'type':u'student'
            },
        {
            'id':2,
            'name':u'test2',
            'passwd':u'test2',
            'type':u'student'
            }
        ]

@app.route('/snail/api/v0.1/users', methods=['GET'])
def get_users():
    return jsonify({'users': users})
@app.route('/snail/api/v0.1/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = filter(lambda t: t['id'] == user_id, users)
    if len(user) == 0:
        abort(404)
    return jsonify({'user': user[0]})

if __name__ == '__main__':
    app.run(debug=True)
