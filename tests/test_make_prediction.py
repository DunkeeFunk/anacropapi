from unittest import TestCase
import base64
import uuid
from api.models import *
from api import create_app, db
from werkzeug.security import generate_password_hash
import json


class TestMake_prediction(TestCase):

    def setUp(self):
        self.app = create_app(config_name="testing")
        self.client = self.app.test_client
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(b'jimmy@gmail.com:password').decode('utf-8')
        }
        self.auth_headers = {
            "Content-Type": "application/json",
            "x-access-token": ""
        }

        self.make_prediction ={
            "light": "True",
            "temp": "21.5",
            "humidity": "65.2"
        }

        with self.app.app_context():
            # create all tables
            db.drop_all()
            db.create_all()
            new_user = Users(user_name="jimmy@gmail.com", public_id=str(uuid.uuid4()),
                             password=generate_password_hash("password", method="sha256"), admin=False)
            new_user.save()

    def test_make_prediction(self):
        res = self.client().get('/login', headers=self.headers)
        result = json.loads(res.data.decode())
        self.auth_headers['x-access-token'] = result['token']
        res_predict = self.client().post('/predict', headers=self.auth_headers, data=json.dumps(self.make_prediction))
        result = json.loads(res_predict.data.decode())
        print(result)
        self.assertIsNotNone(result['knn_prediction'])
        self.assertIsNotNone(result['svm_prediction'])
        self.assertIsNotNone(result['rf_prediction'])
        self.assertIsNotNone(result['KNN_accuracy'])
        self.assertIsNotNone(result['SVM_accuracy'])
        self.assertIsNotNone(result['RF_accuracy'])

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()
