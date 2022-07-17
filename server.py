from typing import Union
import os

from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask.views import MethodView
from flask_login import LoginManager, login_required, login_user, current_user
from sqlalchemy import and_
from sqlalchemy.exc import DataError
from dotenv import load_dotenv


app = Flask('app')
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


@login_manager.request_loader
def load_user_from_request(request):
    token = request.headers.get('Authorization')
    if token:
        token = token.replace('Token ', '')
        with Session() as session:
            try:
                user = session.query(User).filter_by(token=token).first()
                if user is None:
                    raise HTTPError(401, "invalid token")
                return user
            except DataError:
                raise HTTPError(401, "invalid token")
    return None


class HTTPError(Exception):
    def __init(self, status_code: int, message: Union[str, list, dict]):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HTTPError)
def handle_invalid_usage(error):
    response = jsonify({'message': error.args[1]})
    response.status_code = error.args[0]
    return response


class AdvertisementView(MethodView):

    def get(self, adv_id=None):
        with Session() as session:
            if adv_id is None:
                advertisements = session.query(Advertisement).filter_by(deleted=False).all()
                response = [adv.to_dict() for adv in advertisements]
                return jsonify(response)
            advertisement = session.query(Advertisement).filter(
                and_(
                    Advertisement.id == adv_id,
                    Advertisement.deleted == False
                )
            ).first()
            if advertisement is None:
                raise HTTPError(400, "Incorrect advertisement ID")
            return advertisement.to_dict(), 200

    @login_required
    def post(self):
        with Session() as session:
            advertisement_data = validate(request.json, CreateAdvertisementModel)
            new_advertisement = Advertisement.create_advertisement(
                session,
                owner_id=current_user.id,
                **advertisement_data
            )
            return new_advertisement.to_dict(), 201

    @login_required
    def patch(self, adv_id: int):
        with Session() as session:
            data = request.json
            advertisement = session.query(Advertisement).filter(
                and_(
                    Advertisement.id == adv_id,
                    Advertisement.deleted == False
                )
            ).first()
            if advertisement is None:
                raise HTTPError(400, "Incorrect advertisement ID")
            elif advertisement.owner_id != current_user.id:
                raise HTTPError(403, "You are not advertising owner")
            advertisement.title = data.get('title', advertisement.title)
            advertisement.description = data.get('description', advertisement.description)
            session.add(advertisement)
            session.commit()
            return advertisement.to_dict(), 200

    @login_required
    def delete(self, adv_id: int):
        with Session() as session:
            advertisement = session.query(Advertisement).filter(
                and_(
                    Advertisement.id == adv_id,
                    Advertisement.deleted == False
                )
            ).first()
            if advertisement is None:
                raise HTTPError(400, "Incorrect advertisement ID")
            elif advertisement.owner_id != current_user.id:
                raise HTTPError(403, "You are not advertising owner")
            advertisement.deleted = True
            session.commit()
            return '', 204


def login():
    login_data = request.json
    with Session() as session:
        user = session.query(User).where(
            User.name == login_data['user_name']
        ).first()
        if user is None or not user.check_password(login_data['password']):
            raise HTTPError(401, "incorrect name or password")
    login_user(user)
    return user.to_dict()


def register():
    with Session() as session:
        register_data = validate(request.json, CreateUserModel)
        try:
            new_user = User.register(session, **register_data)
            if new_user is None:
                raise HTTPError(401, "name or e-mail is already exists, choose other credentials")
        except KeyError:
            raise HTTPError(404, 'name, password and e-mail is required fields')
        return new_user.to_dict(), 201


app.add_url_rule('/advertisements/', view_func=AdvertisementView.as_view('get_advertisements'), methods=['GET'])
app.add_url_rule('/advertisements/', view_func=AdvertisementView.as_view('create_advertisement'), methods=['POST'])
app.add_url_rule('/advertisements/<int:adv_id>/', view_func=AdvertisementView.as_view('patch_advertisement'),
                 methods=['GET', 'PATCH', 'DELETE'])
app.add_url_rule('/login/', view_func=login, methods=['POST'])
app.add_url_rule('/register/', view_func=register, methods=['POST'])

if __name__ == "__main__":
    from db import User, Advertisement, Session
    from validators import validate, CreateAdvertisementModel, CreateUserModel
    app.run()
