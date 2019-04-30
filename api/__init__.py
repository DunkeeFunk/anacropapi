from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
from decimal import *
# local imports
from instance.config import app_config
from ml.wrangler import MLWrapper

# initialize sql-alchemy
db = SQLAlchemy()


def create_app(config_name):

    from api.models import Users, Measurements, Plants, Models

    api = Flask(__name__, instance_relative_config=True)
    api.config.from_object(app_config[config_name])
    api.config.from_pyfile('config.py')
    api.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(api)  # bind the database to the app
    # machine learning class
    ml = MLWrapper()
    ml.wrangle_data()
    ml.model_trainer()

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
        if not current_user.admin:
            return jsonify({'message': 'Cannot perform that function!'})
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
        if not current_user.admin:
            return jsonify({'message': 'Cannot perform that function!'})

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

        # check out Users.delete function in the models
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

    @api.route('/user/plant', methods=['DELETE', 'POST'])
    @token_required
    def handle_plants(current_user):

        if request.method == "POST":
            try:
                # get data in from request  as json object
                data_in = request.get_json()
                # create a new plant
                new_plant = Plants(plant_name=data_in['plantname'], plant_type=data_in['planttype'],
                                   sensor_id=data_in['sensorid'], public_id=current_user.public_id)
                # save plant in the db
                new_plant.save()
                # return a message to the user letting them no it was successful
                return jsonify({'message': 'plant created'})
            except:
                return jsonify({'message': 'plant not created check db schema!'})

        if request.method == "DELETE":
            try:
                # get the data in same as above
                data_in = request.get_json()
                # do a query for the plant
                plant_query = Plants.query.filter_by(sensor_id=data_in['sensorid']).first()
                # delete from db and save
                plant_query.delete()

                return jsonify({'message': 'plant deleted'})
            except:
                return jsonify({'message': 'plant not deleted check db schema!'})

    @api.route('/sensor/datain', methods=['POST'])
    @token_required
    def handle_incoming_data(current_user):
        data_in = request.get_json()

        light = False
        if data_in['light'] == '1':
            light = True
        # make a measurement
        new_measur = Measurements(username=data_in['sensorid'], sensor_name=data_in['sensorname'],
                                  temp=Decimal(data_in['temp']), soil_m=int(data_in['soilm']),
                                  humidity=Decimal(data_in['humidity']), light=light)
        new_measur.save()
        return jsonify({'message': 'data received'})

    @api.route('/sensor/mostrecent/entry', methods=['GET'])
    @token_required
    def get_most_recent(current_user):

        measurement = Measurements.get_most_recent()

        return jsonify({'temp': str(measurement.temp),
                        'soilm': str(measurement.soil_m),
                        'humidity': str(measurement.humidity),
                        'light': str(measurement.light)})

    @api.route('/modeltrainer', methods=['GET'])
    @token_required
    def model_trainer(current_user):
        # this route should only be called by an admin
        if not current_user.admin:
            return jsonify({'message': 'Cannot perform that function!'})

        try:
            ml.model_trainer()
            return jsonify({'message': "models successfully trained and pickles dumped !"})
        except:
            return jsonify({'message': "model training failed !"})

    @api.route('/predict', methods=['POST'])
    @token_required
    def make_prediction(current_user):
        data_in = request.get_json()

        light = False
        if data_in['light'] == 'True':
            light = True
        knn, accur = ml.knn_classify(Decimal(data_in['temp']),
                                     Decimal(data_in['humidity']),
                                     light)
        svm, acc = ml.svm_classify(Decimal(data_in['temp']),
                                   Decimal(data_in['humidity']),
                                   light)
        rf, a = ml.random_forrest_classify(Decimal(data_in['temp']),
                                           Decimal(data_in['humidity']),
                                           light)
        return jsonify({'knn_prediction': str(knn), 'KNN_accuracy': accur,
                        'svm_prediction': str(svm), 'SVM_accuracy': acc,
                        'rf_prediction': str(rf), 'RF_accuracy': a})

    return api

