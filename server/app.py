from flask import Flask, request, jsonify, session
from flask_restful import Api, Resource
from models import db, User, Recipe
from config import app, bcrypt
from sqlalchemy.exc import IntegrityError, DataError

api = Api(app)

class Signup(Resource):
    def post(self):
        try:
            json_data = request.get_json()
            username = json_data.get('username')
            password = json_data.get('password')
            bio = json_data.get('bio')
            image_url = json_data.get('image_url')

            if not username or not password:
                return {'error': 'Username and password cannot be blank'}, 422

            new_user = User(
                username=username,
                bio=bio,
                image_url=image_url
            )
            new_user.password_hash = password

            db.session.add(new_user)
            db.session.commit()
            return new_user.to_dict(), 201

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already taken'}, 422
        except ValueError as e:
            return {'error': str(e)}, 422
        except Exception as e:
            db.session.rollback()
            return {'error': 'An unexpected error occurred'}, 500

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        user = User.query.get(user_id)
        if user:
            return user.to_dict()
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'error': 'Username and password are required'}, 422

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'error': 'Invalid credentials'}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id')
            return '', 401
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return [recipe.to_dict() for recipe in recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 422

        json = request.get_json()
        title = json.get('title')
        instructions = json.get('instructions')
        minutes_to_complete = json.get('minutes_to_complete')

        if not all([title, instructions, minutes_to_complete]):
            return {'error': 'All fields are required'}, 422

        try:
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()
            return new_recipe.to_dict(), 201
        except ValueError as e:
            return {'error': str(e)}, 422
        except DataError as e:
            db.session.rollback()
            return {'error': 'Invalid data provided'}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(debug=True, port=5555)
