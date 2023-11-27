from sqlalchemy import Column, String, Integer,Boolean
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    first_name = Column(String)
    last_name = Column(String)
    role = Column(String)
    is_active=Column(Boolean,default=False)
    is_admin_approved=Column(String,default="pending")
    hashed_password = Column(String)
