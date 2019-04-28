from unittest import TestCase
import base64
import uuid
from api.models import *
from api import create_app, db
from werkzeug.security import generate_password_hash
import json


class TestHandle_plants(TestCase):

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

        self.good_plant = {
            "plantname": "Jimmy's Tomato",
            "sensorid": "RaspberryPi1",
            "planttype": "F12 Tomato"
        }

        with self.app.app_context():
            # create all tables
            db.drop_all()
            db.create_all()
            new_user = Users(user_name="jimmy@gmail.com", public_id=str(uuid.uuid4()),
                             password=generate_password_hash("password", method="sha256"), admin=False)
            new_user.save()

    def test_add_handle_plants(self):
        res = self.client().get('/login', headers=self.headers)
        result = json.loads(res.data.decode())
        self.auth_headers['x-access-token'] = result['token']
        res_plant = self.client().post('/user/plant', headers=self.auth_headers, data=json.dumps(self.good_plant))
        result = json.loads(res_plant.data.decode())
        self.assertEqual(result['message'], "plant created")

    def test_delete_handle_plants(self):
        res = self.client().get('/login', headers=self.headers)
        result = json.loads(res.data.decode())
        self.auth_headers['x-access-token'] = result['token']
        res_plant = self.client().post('/user/plant', headers=self.auth_headers, data=json.dumps(self.good_plant))
        result = json.loads(res_plant.data.decode())
        self.assertEqual(result['message'], "plant created")
        res_del_plant = self.client().delete('/user/plant', headers=self.auth_headers, data=json.dumps(self.good_plant))
        res_del = json.loads(res_del_plant.data.decode())
        self.assertEqual(res_del['message'], "plant deleted")

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()