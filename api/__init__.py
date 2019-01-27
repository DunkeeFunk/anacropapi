from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
# local imports
from instance.config import app_config

# initialize sql-alchemy
db = SQLAlchemy()


def create_app(config_name):

    from api.models import Users, Measurements

    api = Flask(__name__, instance_relative_config=True)
    api.config.from_object(app_config[config_name])
    api.config.from_pyfile('config.py')
    api.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(api)

    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None

            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']

            if not token:
                return jsonify({'message': 'Token is missing!'}), 401

            try:
                # data = jwt.decode(token, app.config['SECRET_KEY'])
                data = jwt.decode(token, os.getenv('SECRET_KEY'))
                current_user = Users.query.filter_by(public_id=data['public_id']).first()
            except:
                return jsonify({'message': 'Token is invalid!'}), 401

            return f(current_user, *args, **kwargs)

        return decorated

    @api.route('/user', methods=['GET'])
    @token_required
    def get_all_users(current_user):
        # we don't use current user because I didn't want to but if you want to make this an admin only func you can
        # just un comment the two lines below
        # if not current_user.admin:
            # return jsonify({'message': 'Cannot perform that function!'})
        users = Users.query.all()

        output = []

        for user in users:
            user_data = {}
            user_data['public_id'] = user.public_id
            user_data['name'] = user.user_name
            user_data['password'] = user.password
            user_data['admin'] = user.admin
            output.append(user_data)

        return jsonify({'users': output})

    @api.route('/user/<public_id>', methods=['GET'])
    @token_required
    def get_one_user(current_user, public_id):

        user = Users.query.filter_by(public_id=public_id).first()

        if not user:
            return jsonify({'message': 'No user found!'})

        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        return jsonify({'user': user_data})

    @api.route('/user', methods=['POST'])
    @token_required
    def create_user(current_user):
        if not current_user.admin:
            return jsonify({'message': 'Cannot perform that function!'})

        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')

        new_user = Users(user_name=data['name'], public_id=str(uuid.uuid4()), password=hashed_password, admin=False)
        # db.session.add(new_user)
        # db.session.commit()
        new_user.save()

        return jsonify({'message': 'New user created!'})

    @api.route('/user/<public_id>', methods=['PUT'])
    @token_required
    def promote_user(current_user, public_id):
        # if not current_user.admin:
            # return jsonify({'message': 'Cannot perform that function!'})

        user = Users.query.filter_by(public_id=public_id).first()

        if not user:
            return jsonify({'message': 'No user found!'})

        user.admin = True
        db.session.commit()

        return jsonify({'message': 'The user has been promoted!'})

    @api.route('/user/<public_id>', methods=['DELETE'])
    @token_required
    def delete_user(current_user, public_id):
        if not current_user.admin:
            return jsonify({'message': 'Cannot perform that function!'})

        user = Users.query.filter_by(public_id=public_id).first()

        if not user:
            return jsonify({'message': 'No user found!'})

        # db.session.delete(user)
        # db.session.commit()
        user.delete()

        return jsonify({'message': 'The user has been deleted!'})

    @api.route('/login')
    def login():
        auth = request.authorization

        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        user = Users.query.filter_by(user_name=auth.username).first()

        if not user:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id': user.public_id,
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, os.getenv('SECRET_KEY'))

            return jsonify({'token': token.decode('UTF-8')})

        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    return api

