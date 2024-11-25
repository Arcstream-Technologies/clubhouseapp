from pydantic import constr
from pydantic import BaseModel, EmailStr, constr, UUID4, Field, validator
from datetime import datetime
# Base model with common user fields (if any in the future)
class UserBase(BaseModel):
    pass  # This is intended for common fields like address, etc.

# Response model for user details
class UserResponse(UserBase):
    id: UUID4                 # Assuming UUID4 is the type used for user ID
    created_at: datetime      # Timestamp of user creation
    first_name: str           # User's first name
    last_name: str            # User's last name
    email: EmailStr           # User's email (validated)
    password: str             # Note: In practice, avoid returning the password

    class Config:
        orm_mode = True        # This allows Pydantic to work with ORM like SQLAlchemy by mapping field names

# Model for user registration input
class UserRegistration(BaseModel):
    first_name: str
    last_name: str
    phone_number: str
    email: str
    password: str
    confirm_password: str
    
# Model for creating a user (e.g., for internal use)
class UserCreate(BaseModel):
    email: EmailStr          # User's email (validated)
    password: str            # User's password

# Token response model
class Token(BaseModel):
    access_token: str        # The JWT access token
   

# Model for login request input
class LoginRequest(BaseModel):
    username: EmailStr       # Username is expected to be an email
    password: str            # User's password

    class Config:
        schema_extra = {
            "example": {       # JSON schema example for documentation purposes
                "username": "lathadwarapu@gmail.com",
                "password": "Vani@2345"
            }
        }

# Model for OTP request
class OTPRequest(BaseModel):
    email: EmailStr          # User's email to send OTP for verification

class OTPVerification(BaseModel):
    email: str
    otp: str

class OTPVerificationSuccess(BaseModel):
    message: str
    email: str

# Model for forgot password request
class ForgotPasswordRequest(BaseModel):
    email: EmailStr          # User's email to request password reset

class PasswordResetRequest(BaseModel):
    new_password: constr  # Enforce minimum password length
    confirm_password: constr

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v