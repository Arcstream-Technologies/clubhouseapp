from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from models import Base
import os 

# Replace 'your_database_url' with your actual PostgreSQL database URL
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:Madhu%402345@localhost:5432/cb1"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)