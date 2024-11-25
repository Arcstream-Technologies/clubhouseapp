from sqlalchemy import Column, String, DateTime,Integer
from sqlalchemy.ext.declarative import declarative_base
import uuid as uuid_pkg
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID as PG_UUID  # Use this if you're using PostgreSQL

# SQLAlchemy Base
Base = declarative_base()

class UUIDModelBase(Base):
    """Base class for UUID-based models."""
    __abstract__ = True  # This class should not be instantiated directly

    # Define the UUID column as a SQLAlchemy Column
    uuid = Column(PG_UUID(as_uuid=True), default=uuid_pkg.uuid4, primary_key=True, index=True, nullable=False)

class User(UUIDModelBase):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    phone_number = Column(String)  # Add this field if it's part of your model
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.now)