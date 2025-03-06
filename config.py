import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

S3_BUCKET = os.environ.get("S3_BUCKET") 
S3_KEY = os.environ.get("S3_KEY") 
S3_SECRET = os.environ.get("S3_SECRET") 
S3_REGION = os.environ.get("S3_REGION")  # e.g., 'ap-northeast-2'

SECRET_KEY = os.environ.get('SECRET_KEY')

WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY')

SQLALCHEMY_LOCAL_DATABASE_URI = os.environ.get('LOCAL_DATABASE_URI')

SQLALCHEMY_RDS_DATABASE_URI = os.environ.get('RDS_DATABASE_URI')
