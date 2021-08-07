from os import access
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
from flask import Blueprint, app, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
# import validators
# from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# from flasgger import swag_from
from src.database import User, db

auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth.post('/register')
def register():
    return "User created"

# @auth.post('/login')
# @swag_from('./docs/auth/login.yaml')
# def login():
#     email = request.json.get('email', '')
#     password = request.json.get('password', '')

#     user = User.query.filter_by(email=email).first()

#     if user:
#         is_pass_correct = check_password_hash(user.password, password)

#         if is_pass_correct:
#             refresh = create_refresh_token(identity=user.id)
#             access = create_access_token(identity=user.id)

#             return jsonify({
#                 'user': {
#                     'refresh': refresh,
#                     'access': access,
#                     'username': user.username,
#                     'email': user.email
#                 }

#             }), HTTP_200_OK

#     return jsonify({'error': 'Wrong credentials'}), HTTP_401_UNAUTHORIZED


@auth.get("/me")
#@jwt_required()
def me():
    # user_id = get_jwt_identity()
    # user = User.query.filter_by(id=user_id).first()
    # return jsonify({
    #     'username': user.username,
    #     'email': user.email
    # }), HTTP_200_OK
    return {"user" : "me"}


# @auth.get('/token/refresh')
# @jwt_required(refresh=True)
# def refresh_users_token():
#     identity = get_jwt_identity()
#     access = create_access_token(identity=identity)

#     return jsonify({
#         'access': access
#     }), HTTP_200_OK
