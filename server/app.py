#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data= request.get_json()
        username= data.get('username')
        password= data.get('password')
        image_url= data.get('image_url')
        bio= data.get('bio')
        if not username or not password:
            return {'error': 'Username and password are required'}, 422
        
        if User.query.filter_by(username=username).first():
            return {'error': 'Username already exists'}, 422
        
        new_user = User(username=username, image_url=image_url, bio=bio)
        new_user.password_hash = password

        db.session.add(new_user)
        db.session.commit()
        return {
            "id": new_user.id,
            "username": new_user.username,
            "image_url": new_user.image_url,
            "bio": new_user.bio
        }, 201
         
        
        
        

class CheckSession(Resource):
    def get (self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }, 200
            
        return {'error': 'Not logged in'}, 401

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
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200
        else:
            return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        user=session.get('user_id')
        if user:
          session.pop('user_id')
          return {'message': 'Logged out successfully'}, 204
        return {'error': 'Not logged in'}, 401
    

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Not logged in'}, 401
        
        recipes = Recipe.query.all()
        recipe_data = [
            {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            }
            for recipe in recipes
        ]
        return recipe_data, 200
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Not logged in'}, 401
        
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if not title or not instructions or not minutes_to_complete:
            return {'error': 'Title, instructions, and minutes to complete are required'}, 422
        try:
             new_recipe = Recipe(
                        title=title,
                        instructions=instructions,
                        minutes_to_complete=minutes_to_complete,
                        user_id=user_id
                    )
        
             db.session.add(new_recipe)
             db.session.commit()

             return {
            "id": new_recipe.id,
            "title": new_recipe.title,
            "instructions": new_recipe.instructions,
            "minutes_to_complete": new_recipe.minutes_to_complete,
            "user": {
                "id": new_recipe.user.id,
                "username": new_recipe.user.username,
                "image_url": new_recipe.user.image_url,
                "bio": new_recipe.user.bio
            }
        }, 201

        except ValueError as ve:
            return {'error': str(ve)}, 422
        except Exception as e:
            return {'error': 'An error occurred while creating the recipe'}, 500
         
        

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)