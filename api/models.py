from api import db


class Users(db.Model):
    """This class represents the users table."""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80))
    public_id = db.Column(db.String(50), unique=True)  # this is the foreign key for users plants
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    plants = db.relationship('Plants', backref='users', lazy=True)

    def __init__(self, user_name, public_id, password, admin):
        """initialise with user details / passwords are hashed remember"""
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


class Plants(db.Model):
    """This class represents the plants table"""

    __tablename__ = 'plants'

    plant_id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.String(50), db.ForeignKey('users.public_id'), nullable=False)
    plant_name = db.Column(db.String(255))
    plant_type = db.Column(db.String(50))
    sensor_id = db.Column(db.String(12), unique=True)  # Foreign key for measurements
    measurements = db.relationship('Measurements', backref='plants', lazy=True)
    models = db.relationship('Models', backref='plants', lazy=True)  # new code

    def __init__(self, plant_name, plant_type, sensor_id, public_id):
        self.plant_name = plant_name
        self.plant_type = plant_type
        self.sensor_id = sensor_id
        self.owner_id = public_id

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def save(self):
        db.session.add(self)
        db.session.commit()


class Measurements(db.Model):
    """This class represents the measurements table"""

    __tablename__ = 'measurements'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('plants.sensor_id'), nullable=False)
    sensor_name = db.Column(db.String(255))
    temp = db.Column(db.DECIMAL())
    soil_m = db.Column(db.Integer)
    humidity = db.Column(db.DECIMAL())
    light = db.Column(db.Boolean)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __init__(self, username, sensor_name, temp, soil_m, humidity, light):
        """initialize with stats."""
        self.username = username
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


class Models(db.Model):
    """This class represents the models table"""

    __tablename__ = 'models'

    model_id = db.Column(db.Integer, primary_key=True)
    xs = db.Column(db.String(255))
    ys = db.Column(db.String(255))
    model_name = db.Column(db.String(80), nullable=False)
    sensor_name = db.Column(db.String(255), db.ForeignKey('plants.sensor_id'))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __init__(self, xs, ys, model_name, sensor_name):
        """initialize with processed data."""
        self.xs = xs
        self.ys = ys
        self.model_name = model_name
        self.sensor_name = sensor_name








