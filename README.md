$ export FLASK_APP="application.py"

$ export APP_SETTINGS="development"

$ export SECRET_KEY="a-long-string-of-random-characters-CHANGE-TO-YOUR-LIKING"

$ export DATABASE_URL="postgresql://localhost/flask_api"
^^^^ change this to your connection string from AWS ^^^
export DATABASE_URL="postgresql://michael:SamsungS7@localhost:5432/flask_api" << local con string
