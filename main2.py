import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Body
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from jose import jwt
from passlib.context import CryptContext
import logging
import random
import string
from dotenv import load_dotenv
from typing import Dict

# Import your local modules (adjust paths as necessary)
from db import SessionLocal, engine  
from models import Base, User         
from schemas import (
    UserRegistration,
    Token,
    LoginRequest,
    UserResponse,
    OTPVerification,
    OTPVerificationSuccess,
    PasswordResetRequest,
)

# Load environment variables
load_dotenv()

# Configuration settings.
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Email Configuration
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# Create database tables
Base.metadata.create_all(bind=engine)

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Password and Authentication Setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI App
app = FastAPI()

# Pending Registrations Storage
class PendingRegistration:
    def __init__(self, email, otp, data, created_at):
        self.email = email
        self.otp = otp
        self.data = data
        self.created_at = created_at

pending_registrations: Dict[str, PendingRegistration] = {}

# Database Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility Functions
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def send_email(subject: str, recipient: str, body: str):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        text = msg.as_string()
        server.sendmail(EMAIL_USER, recipient, text)
        server.quit()
        logger.debug(f"Email sent to {recipient}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {recipient}: {str(e)}")
        return False

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

@app.post("/register")
def register_user(user: UserRegistration, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        logger.info(f"Registration request received for {user.email}")
        
        if not user.email or not user.password:
            raise HTTPException(status_code=400, detail="Invalid input data")
        
        existing_user = get_user_by_email(db, user.email)
        if existing_user:
            logger.warning(f"Registration attempt for existing email: {user.email}")
            raise HTTPException(status_code=400, detail="Email already registered")
        
        otp = generate_otp()
        logger.debug(f"Generated OTP for {user.email}: {otp}")
        
        pending_registrations[user.email] = PendingRegistration(
            email=user.email,
            otp=otp,
            data=user.dict(),
            created_at=datetime.now()
        )
        
        subject = "Your Registration OTP"
        body = f"Your OTP is: {otp}. It will expire in 10 minutes."
        
        background_tasks.add_task(send_email, subject, user.email, body)
        
        logger.info(f"OTP sent to {user.email}")
        
        return {
            "message": "OTP sent successfully",
            "first_name": user.first_name,
            "last_name": user.last_name,
            "uuid": "Generated during registration",
            "email": user.email,
        }
    
    except HTTPException:
        raise 
    
    except Exception as e:
        logger.exception(f"Unexpected error during registration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/verify-otp")
def verify_otp(verification: OTPVerification, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        logger.info(f"OTP verification request for {verification.email}")
        
        if not verification.email or not verification.otp:
            raise HTTPException(status_code=400, detail="Invalid input data")
        
        pending_reg = pending_registrations.get(verification.email)
        
        if not pending_reg:
            logger.warning(f"No pending registration for {verification.email}")
            raise HTTPException(status_code=400, detail="No pending registration found")
        
        if (datetime.now() - pending_reg.created_at).total_seconds() > 600:
            logger.warning(f"OTP expired for {verification.email}")
            del pending_registrations[verification.email]
            raise HTTPException(status_code=400, detail="OTP has expired")
        
        if pending_reg.otp != verification.otp:
            logger.warning(f"Invalid OTP for {verification.email}")
            raise HTTPException(status_code=400, detail="Invalid OTP")
        
        new_user = User(
            first_name=pending_reg.data['first_name'],
            last_name=pending_reg.data['last_name'],
            email=verification.email,
            phone_number=pending_reg.data['phone_number'],
            password_hash=pwd_context.hash(pending_reg.data['password'])
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        del pending_registrations[verification.email]
        
        logger.info(f"User registered successfully: {verification.email}")
        
        return {
            "message": "Registration successful",
            "email": verification.email,
        }
    
    except HTTPException:
       raise 
    
    except Exception as e:
       logger.exception(f"Unexpected error during OTP verification: {str(e)}")
       raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

@app.post("/login", response_model=Token)
def login_user(login_request: LoginRequest, db: Session = Depends(get_db)):
    try:
       logger.info(f"Login attempt for {login_request.username}")
       
       if not login_request.username or not login_request.password:
           raise HTTPException(status_code=400, detail="Invalid input data")
       
       user = get_user_by_email(db, login_request.username)
       
       if not user:
           logger.warning(f"Login attempt for non-existent user: {login_request.username}")
           raise HTTPException(status_code=400, detail="User not found")
       
       if not pwd_context.verify(login_request.password, user.password_hash):
           logger.warning(f"Invalid password attempt for {login_request.username}")
           raise HTTPException(status_code=400, detail="Invalid credentials")
       
       access_token_expires = timedelta(minutes=30)
       access_token = jwt.encode(
           {"sub": user.email,
           "exp": datetime.utcnow() + access_token_expires},
           SECRET_KEY,
           algorithm=ALGORITHM)

       logger.info(f"Successful login for {login_request.username}")

       return {
           "message": "Login successful",
           "access_token": access_token,
       }
    
    except HTTPException:
       raise 
    
    except Exception as e:
       logger.exception(f"Unexpected error during login: {str(e)}")
       raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/forgot-password")
def forgot_password(email: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
   try:
       logger.info(f"Forgot password request received for {email}")

       if not email:
           raise HTTPException(status_code=400, detail="Invalid input data")

       user = get_user_by_email(db, email)
       
       if not user:
           logger.warning(f"Forgot password attempt for non-existent user: {email}")
           raise HTTPException(status_code=400, detail="User not found")

       otp = generate_otp()
       logger.debug(f"Generated OTP for {email}: {otp}")

       pending_registrations[email] = PendingRegistration(
           email=email,
           otp=otp,
           data=None,
           created_at=datetime.now()
       )

       subject = "Your Password Reset OTP"
       body = f"Your OTP is: {otp}. It will expire in 10 minutes."

       background_tasks.add_task(send_email, subject, email, body)

       logger.info(f"OTP sent to {email}")

       return {
           "message": "OTP sent successfully",
           "email": email,
       }
    
   except HTTPException:
      raise 
    
   except Exception as e:
      logger.exception(f"Unexpected error during forgot password request: {str(e)}")
      raise HTTPException(status_code=500 , detail=f"Forgot password request failed: {str(e)}")

user_sessions = {}

@app.post("/verify-otp-forgot-password", response_model=OTPVerificationSuccess)
def verify_otp_forgot_password(verification: OTPVerification , db: Session = Depends(get_db)):
   try:
      logger.info(f"OTP verification request for forgot password for {verification.email}")

      if not verification.email or not verification.otp:
          raise HTTPException(status_code=400 , detail="Invalid input data")

      pending_reg = pending_registrations.get(verification.email)

      if not pending_reg:
          logger.warning(f"No pending password reset for {verification.email}")
          raise HTTPException(status_code=400 , detail="No pending password reset found")

      if (datetime.now() - pending_reg.created_at).total_seconds() > 600:
          logger.warning(f"OTP expired for {verification.email}")
          del pending_registrations[verification.email]
          raise HTTPException(status_code=400 , detail="OTP has expired")

      if pending_reg.otp != verification.otp:
          logger.warning(f"Invalid OTP for {verification.email}")
          raise HTTPException(status_code=400 , detail="Invalid OTP")

      user_sessions[verification.email] = verification.email

      del pending_registrations[verification.email]

      logger.info(f"OTP verified successfully for {verification.email}")

      return OTPVerificationSuccess(
          message="OTP verified successfully",
          email=verification.email,
      )
    
   except HTTPException:
      raise 
    
   except Exception as e:
      logger.exception(f"Unexpected error during OTP verification for forgot password: {str(e)}")
      raise HTTPException(status_code=500 , detail=f"OTP verification for forgot password failed: {str(e)}")

@app.post("/reset-password", response_model=dict)
def reset_password(
    new_password: str = Body(..., embed=True),
    confirm_password: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    try:
        logger.info("Reset password request received")

        # Validate input data
        if not new_password or not confirm_password:
            raise HTTPException(status_code=400, detail="Password fields cannot be empty")

        if new_password != confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        # Retrieve the email from the session
        email = next((email for email in user_sessions.values()), None)

        if not email:
            logger.warning("No email found in the session")
            raise HTTPException(status_code=400, detail="No email found in session. Please verify your OTP first.")

        # Check if the user exists
        user = get_user_by_email(db, email)

        if not user:
            logger.warning(f"Reset password attempt for non-existent user: {email}")
            raise HTTPException(status_code=404, detail="User not found")

        # Update the user's password
        user.password_hash = pwd_context.hash(new_password)
        db.commit()
        db.refresh(user)

        # Clear the session
        user_sessions.pop(email, None)

        logger.info(f"Password reset successfully for {email}")

        return {"message": "Password reset successfully"}

    except HTTPException as e:
        logger.error(f"HTTPException during password reset: {str(e)}")
        raise

    except Exception as e:
        logger.exception(f"Unexpected error during password reset: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
