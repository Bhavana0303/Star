from fastapi import APIRouter,Depends,HTTPException,status
from pydantic import BaseModel,EmailStr
from typing import Optional
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
import jwt
import models
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


SECRET_KEY = "jikldkaoijeofijaepeo897hjk1"
ALGORITHM = "HS256"


class CreateUser(BaseModel):
    username: str
    email: EmailStr
    first_name: str
    last_name: str
    role:str
    password:str


models.Base.metadata.create_all(bind=engine)
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    # responses={401: {"user": "Not authorized"}}
)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def get_password_hash(password):
    return bcrypt_context.hash(password)


def verify_password(plain_password,hashed_password):
    return bcrypt_context.verify(plain_password,hashed_password)


def authenticate_user(username: str, password: str, db):

    user = db.query(models.User)\
        .filter(models.User.username == username) \
        .filter(models.User.is_active == True)\
        .first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int, role: str,
                        expires_delta: Optional[timedelta] = None):
    encode = {"user": username, "user_id": user_id, "role": role}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encode.update({"exp": expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("user")
        user_id: int = payload.get("user_id")
        role: str = payload.get("role")
        # Extract the "role" from the payload
        if user_id is None or username is None or role is None:
            raise get_user_exception()
        return {'username': username, 'user_id': user_id, 'role': role}
    except:
        raise get_user_exception()


@router.post("/create/user")
async def create_new_user(create_user: CreateUser, db: Session = Depends(get_db)):
    # Check if the user already exists
    existing_user = db.query(models.User).filter(models.User.username == create_user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    # Hash the password before storing it
    hashed_password = get_password_hash(create_user.password)

    is_admin_approved = "approved" if create_user.role == "Admin" else "pending"
    is_active=True if create_user.role=="Admin" else False

    # Create a new user with the provided details
    new_user = models.User(
        username=create_user.username,
        email=create_user.email,
        first_name=create_user.first_name,
        last_name=create_user.last_name,
        role=create_user.role,
        hashed_password=hashed_password,
        is_admin_approved=is_admin_approved,
        is_active=is_active
    )
    db.add(new_user)
    db.commit()
    if create_user.role != "Admin":
        await notify_admin(create_user.username, create_user.email)

    return {"message": "User created successfully", "status_code": status.HTTP_201_CREATED}


@router.get("/users")
async def get_all_users(db: Session = Depends(get_db)):
        query=db.query(models.User).all()
        if query is None:
         return {"message": "no users found", "status": status.HTTP_404_NOT_FOUND}

        return {"message": "successful", "data": query, "status": status.HTTP_200_OK}


@router.get("/current_user")
async def read_current_user(user: dict = Depends(get_current_user)):
    if user is None:
        return {"detail": "User not found"}
    return user


@router.post("/token")
def login_for_access_token(form_data : OAuth2PasswordRequestForm = Depends(),
                            db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password,db)
    if not user:
        raise token_exception()
    token_expires = timedelta(40)
    token = create_access_token(user.username, user.id,user.role, expires_delta=token_expires)

    return { "access_token": token, "token_type": "Bearer"}
#Exceptions


def get_user_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail = "Could not validate credentials",
        headers = {"WWW-Authenticate" : "Bearer"}
        )
    return credentials_exception


def token_exception():
    token_exception_reponse = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"}

    )
    return token_exception_reponse


async def notify_admin(username: str, email: str):
    sender_email="noreply@stargleameducation.com"
    admin_email="bhavana.nagella@maangtechnologies.com"
    api_domain = "http://127.0.0.1:8000"
    subject = "New User Registration - Approval Required"

    action_link = f"{api_domain}/docs"

    body = f"Hi Admin,\n\nA new user with the username {username} and email {email} has registered and requires approval.\n\n"
    body += f"Click the following link to manage the registration:\n\n"
    body += f"Action: {action_link}\n\n"
    body += "Regards,\nStargleam Education"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = sender_email
    smtp_password = "password"  #google app password

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = admin_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, admin_email, message.as_string())

@router.put("/admin/action")
async def admin_action(
    email: str ,
    action: str,
    db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if action == "approve":
        user.is_admin_approved = "approved"
        user.is_active = True
        db.commit()
        return {"message": "User registration approved successfully"}

    elif action == "reject":
        user.is_admin_approved = "rejected"
        user.is_active = False
        db.commit()
        return {"message": "User registration rejected successfully"}

    else:
        raise HTTPException(status_code=400, detail="Invalid action, use 'approve' or 'reject'")



