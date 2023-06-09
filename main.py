from fastapi import FastAPI, Depends, HTTPException, status, Request
from pydantic import BaseModel
from fastapi.security import APIKeyHeader
import bcrypt
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import secrets
from passlib.context import CryptContext

from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy_utils import create_database, database_exists

#database config
DATABASE_URL = "sqlite:///./sql_app.db"
#DATABASE_URL = "postgresql://postgres@localhost/your_database"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# User Model
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    api_key = Column(String)
    expiry_date = Column(DateTime)

# Create database tables if they don't exist
if not database_exists(engine.url):
    create_database(engine.url)
Base.metadata.create_all(bind=engine)

# Pydantic model for user registration
class UserRegistration(BaseModel):
    username: str
    email: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    api_key : str
    expiry_date: datetime

class Token(BaseModel):
    access_token: str
    token_type: str

app = FastAPI()

# Hashing Configuration for encrypting API key
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def generate_api_key():
    return str(secrets.randbelow(10**10)).zfill(10)

def encrypt_api_key(api_key):
    return bcrypt.hashpw(api_key.encode(), bcrypt.gensalt()).decode()


# # Function to generate a random API key
# def generate_api_key():
#     return secrets.token_hex(5)

# # Function to hash the API key
# def encrypt_api_key(api_key):
#     return pwd_context.hash(api_key)

# Function to create a user in the database
def create_user(db, user_data):
    api_key = generate_api_key()
    hashed_api_key = encrypt_api_key(api_key)
    expiry_date = datetime.now() + timedelta(days=365)

    user = User(
        id=secrets.token_hex(10),
        username=user_data.username,
        email=user_data.email,
        api_key=api_key,
        expiry_date=expiry_date
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register", response_model=None)
def register_user(user_data: UserRegistration, db: Session = Depends(get_db)):
    user = create_user(db, user_data)
    response = UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        api_key=user.api_key,
        expiry_date=user.expiry_date
    )
    return response

def authenticate_user(api_key: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.api_key == api_key).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    current_time = datetime.now()
    if user.expiry_date < current_time:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

@app.get("/user/authenticate", response_model=Token)
def authenticate(api_key: str = Depends(api_key_header), user: User = Depends(authenticate_user)):
    # access_token = Token(access_token=user.api_key, token_type="bearer")
    # return access_token
    response = {"username": user.username, "email": user.email}
    return response

@app.get("/getUserData")
def get_user_data(api_key: str, db: Session = Depends(get_db), user: User = Depends(authenticate_user)):
    user = db.query(User).filter(User.api_key == api_key).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User does not exist")
    current_time = datetime.now()
    if user.expiry_date < current_time:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail="API key expired")
    response = {"username": user.username, "email": user.email}
    return response



@app.exception_handler(Exception)
async def server_error_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal server error"},
    )

#ennable authentication for getdata
#store encrypted data in db