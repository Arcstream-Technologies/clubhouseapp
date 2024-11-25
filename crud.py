from sqlalchemy.orm import Session
from passlib.context import CryptContext
from models import User
from schemas import UserRegistration

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
"""pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")"""

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user: UserRegistration):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        first_name=user.first_name,
        last_name=user.last_name,
        phone_number=user.phone_number,
        email=user.email,
        password_hash=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user