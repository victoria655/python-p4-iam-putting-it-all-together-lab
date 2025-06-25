from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}  

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    _password_hash= db.Column(db.String())
    image_url = db.Column(db.String(), nullable=True)
    bio= db.Column(db.String())

    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password is write-only")

    
    @password_hash.setter
    def password_hash(self, plaintext):
        self._password_hash = bcrypt.generate_password_hash(plaintext).decode('utf-8')

    def authenticate(self, plaintext):
        return bcrypt.check_password_hash(self._password_hash, plaintext)





class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id= db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100),nullable=False)
    instructions = db.Column(db.String(50), nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user=db.relationship('User', back_populates='recipes')


    @validates('instructions')
    def validate_instructions(self, key, value):
        if len(value)<50:
            raise ValueError("Instructions should have atleast  50 characters")
        return value



    
    