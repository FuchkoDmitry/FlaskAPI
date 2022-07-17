## REST API (backend) для сайта объявлений.
#### Реализованы методы создания/удаления/редактирования/получения всех объявлений или одного  объявления.
#### Создавать объявление может только авторизованный пользователь. Удалять/редактировать может только владелец объявления. 

### для запуска приложения в корне проекта:
* создать виртуальное окружение `python -m venv venv` и перейти в него `source venv/bin/activate`
* установить зависимости `pip install requirements.txt`
* создать файл `.env`. В нем указать переменную `SECRET_KEY`
* Установить БД командой `docker-compose up`
* запустить модуль `server.py`


#### Примеры запросов в файле ```requests.http```