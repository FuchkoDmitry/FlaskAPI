from datetime import datetime
import uuid

from flask_login import UserMixin
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship

from server import bcrypt


BaseModel = declarative_base()
PG_DSN = 'postgresql+psycopg2://admin:1234@127.0.0.1/flask'

engine = create_engine(PG_DSN)

Session = sessionmaker(bind=engine)


class User(BaseModel, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), index=True, nullable=False, unique=True)
    email = Column(String(80), nullable=False, unique=True)
    password = Column(String(100), nullable=False)
    token = Column(UUID(as_uuid=True), default=uuid.uuid4)
    registration_at = Column(DateTime, default=datetime.now())
    advertisements = relationship('Advertisement')

    @classmethod
    def register(cls, session: Session, user_name: str, password: str, email: str):
        new_user = cls(
            name=user_name,
            email=email,
            password=bcrypt.generate_password_hash(password).decode()
        )
        session.add(new_user)
        try:
            session.commit()
            return new_user
        except IntegrityError:
            session.rollback()

    def check_password(self, password: str):
        return bcrypt.check_password_hash(self.password, password.encode())

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'token': self.token,
            'registration_at': self.registration_at
        }


class Advertisement(BaseModel):
    __tablename__ = 'advertisements'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(50), nullable=False)
    description = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    deleted = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    @classmethod
    def create_advertisement(cls, session: Session, title: str, description: str, owner_id: int):
        new_advertisement = cls(
            title=title,
            description=description,
            owner_id=owner_id
        )
        session.add(new_advertisement)
        try:
            session.commit()
            return new_advertisement
        except IntegrityError:
            session.rollback()

    def to_dict(self):
        return {
            'advertisement_id': self.id,
            'owner_id': self.owner_id,
            'title': self.title,
            'description': self.description,
            'created_at': self.created_at
        }


BaseModel.metadata.create_all(engine)
