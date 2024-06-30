from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=True)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship("Recipe", back_populates="user", cascade="all, delete-orphan")

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username cannot be blank.")
        return username

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password cannot be blank")
        hashed_password = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')
        self._password_hash = hashed_password

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'image_url': self.image_url,
            'bio': self.bio
        }

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    user = db.relationship("User", back_populates="recipes")

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError("Title cannot be blank.")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

    @validates('minutes_to_complete')
    def validate_minutes_to_complete(self, key, minutes_to_complete):
        if not isinstance(minutes_to_complete, int):
            raise ValueError("Minutes to complete must be an integer.")
        return minutes_to_complete

    @validates('user_id')
    def validate_user_id(self, key, user_id):
        if not user_id:
            raise ValueError("User ID required.")
        return user_id
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'instructions': self.instructions,
            'minutes_to_complete': self.minutes_to_complete,
            'user_id': self.user_id
        }
