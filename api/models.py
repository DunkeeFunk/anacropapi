from api import db


class Users(db.Model):
    """This class represents the users table."""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80))
    public_id = db.Column(db.String(50), unique=True)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    measurements = db.relationship('Measurements', backref='users', lazy=True)

    def __init__(self, user_name, public_id, password, admin):
        self.user_name = user_name
        self.public_id = public_id
        self.password = password
        self.admin = admin

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def get_user(public_id):
        return Users.query.filter_by(public_id=public_id).first()

    def __repr__(self):
        return "<User: {}>".format(self.user_name)


class Measurements(db.Model):
    """This class represents the measurements table"""

    __tablename__ = 'measurements'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.String(50), db.ForeignKey('users.public_id'), nullable=False)
    sensor_name = db.Column(db.String(255))
    temp = db.Column(db.DECIMAL())
    soil_m = db.Column(db.Integer)
    humidity = db.Column(db.DECIMAL())
    light = db.Column(db.Boolean)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __init__(self, public_id, sensor_name, temp, soil_m, humidity, light):
        """initialize with stats."""
        self.owner_id = public_id
        self.sensor_name = sensor_name
        self.temp = temp
        self.soil_m = soil_m
        self.humidity = humidity
        self.light = light

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_most_recent():
        return Measurements.query.order_by(Measurements.date_created.desc()).first()

    def __repr__(self):
        return "<SensorName: {}>".format(self.sensor_name)


