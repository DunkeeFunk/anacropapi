# You will need to export some environment variables 

```bash
export FLASK_APP=application.py

export APP_SETTINGS=development

export DATABASE_URL=postgresql://localhost/flask_api_db

export SECRET_KEY=changeasyouwish

```
# Install requirements and activate virtual env 

```bash
pip install -r requirements.txt

source venv/bin/activate 
```

# Run the server in virtual env
```bash
python application.py
```

or 

```bash
flask run
```

# AWS EC2 Apache2 Deployment Instructions coming soon... 