from unittest import TestCase
import base64
import uuid
from api.models import *
from api import create_app, db
from werkzeug.security import generate_password_hash
import json


class TestLogin(TestCase):

    def setUp(self):
        self.app = create_app(config_name="testing")
        self.client = self.app.test_client
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(b'jimmy@gmail.com:password').decode('utf-8')
        }
        self.bad_headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(b'fake@gmail.com:password').decode('utf-8')
        }

        with self.app.app_context():
            # create all tables
            db.drop_all()
            db.create_all()
            new_user = Users(user_name="jimmy@gmail.com", public_id=str(uuid.uuid4()),
                             password=generate_password_hash("password", method="sha256"), admin=False)
            new_user.save()

    def test_login_for_token(self):
        res = self.client().get('/login', headers=self.headers)
        result = json.loads(res.data.decode())
        self.assertIsNotNone(result['token'])

    def test_for_no_headers(self):
        res = self.client().get('/login')
        self.assertEqual(res.headers['WWW-Authenticate'], 'Basic realm="Login required!"')
        self.assertEqual(res.status, '401 UNAUTHORIZED')

    def test_bad_user(self):
        res = self.client().get('/login', headers=self.bad_headers)
        self.assertEqual(res.headers['WWW-Authenticate'], 'Basic realm="Login required!"')
        self.assertEqual(res.status, '401 UNAUTHORIZED')

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()
