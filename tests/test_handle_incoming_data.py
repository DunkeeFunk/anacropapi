from unittest import TestCase
import base64
import uuid
from api.models import *
from api import create_app, db
from werkzeug.security import generate_password_hash
import json


class TestHandle_Incoming_Data(TestCase):

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

        self.incoming_data = {
            "sensorid": "RaspberryPi1",
            "sensorname": "RaspberryPi",
            "temp": "25.5",
            "soilm": "1",
            "humidity": "65.4",
            "light": "1"
        }

        with self.app.app_context():
            # create all tables
            db.drop_all()
            db.create_all()
            new_user = Users(user_name="jimmy@gmail.com", public_id=str(uuid.uuid4()),
                             password=generate_password_hash("password", method="sha256"), admin=False)
            new_user.save()
            # new plant creation
            new_plant = Plants(plant_name="Mickeys Tomatos", plant_type='Tomato',
                               sensor_id='RaspberryPi1', public_id=new_user.public_id)
            new_plant.save()

    def test_handle_incoming_data(self):
        res = self.client().get('/login', headers=self.headers)
        result = json.loads(res.data.decode())
        self.auth_headers['x-access-token'] = result['token']
        res_datain = self.client().post('/sensor/datain',
                                        headers=self.auth_headers, data=json.dumps(self.incoming_data))
        result_message = json.loads(res_datain.data.decode())
        self.assertEqual(result_message['message'], 'data received')

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()