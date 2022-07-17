import re

import pydantic

from server import HTTPError

password_regex = re.compile(
    r"^(?=.*[a-z_])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&_])[A-Za-z\d@$!#%*?&_]{8,200}$"
)
email_regex = re.compile(
    r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)"
)


class CreateAdvertisementModel(pydantic.BaseModel):
    title: str
    description: str


class CreateUserModel(pydantic.BaseModel):
    user_name: str
    password: str
    email: str

    @pydantic.validator("password")
    def strong_password(cls, value: str):
        if not re.search(password_regex, value):
            raise ValueError('password to easy')

        return value

    @pydantic.validator("email")
    def correct_email(cls, value: str):
        if not re.search(email_regex, value):
            raise ValueError('incorrect e-mail')

        return value


def validate(unvalidated_data: dict, validation_model):
    try:
        return validation_model(**unvalidated_data).dict()
    except pydantic.ValidationError as er:
        raise HTTPError(400, er.errors())
