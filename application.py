import os

from api import create_app

config_name = os.getenv('APP_SETTINGS')  # this changes when deploying to EC2 Apache Server
application = create_app(config_name)

if __name__ == '__main__':
    application.run()
