#Tạo API với Flask
Đây là tạo API thường
### Install Flask và 1 số package cần thiết

```
pip install flask
pip install flask_sqlalchemy
pip install flask_marshmallow
pip install marshmallow-sqlalchemy
```
Tạo một file crud.py

```
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'crud.sqlite')
db = SQLAlchemy(app)
ma = Marshmallow(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)

    def __init__(self, username, email):
        self.username = username
        self.email = email


class UserSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('username', 'email')


user_schema = UserSchema()
users_schema = UserSchema(many=True)


# Tạo user
@app.route("/user", methods=["POST"])
def add_user():
    username = 'test'
    print(username)
    email = 'test@gmail.com'
    print(email)
    new_user = User(username, email)

    db.session.add(new_user)
    db.session.commit()

    return jsonify(new_user)


# Show thông tin user
@app.route("/user", methods=["GET"])
def get_user():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result.data)


# Show thông tin 1 user
@app.route("/user/<id>", methods=["GET"])
def user_detail(id):
    user = User.query.get(id)
    return user_schema.jsonify(user)


# Chỉnh sửa user
@app.route("/user/<id>", methods=["PUT"])
def user_update(id):
    user = User.query.get(id)
    username = request.json['username']
    email = request.json['email']

    user.email = email
    user.username = username

    db.session.commit()
    return user_schema.jsonify(user)


# Xóa 1 user 
@app.route("/user/<id>", methods=["DELETE"])
def user_delete(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()

    return user_schema.jsonify(user)


if __name__ == '__main__':
    app.run(debug=True)	
```
Trong đoạn code trên có 5 hàm mỗi hàm có 1 nhiệm vụ khác nhau. Thêm sửa xóa đưa ra thông tin của các user bằng cách sử dụng các method khác nhau để sử phân biệt

### Generate SQLite database
Flow theo comandline
```
$ python

>>> from crud import db
>>> db.create_all()

>>>exit()
```
Như vậy ta đã tạo được database với SQLlite  
### Run Flask và Test các API mà mình đã viết
```
$ python crud.py
```
Để test được các API này chúng ta sử dụng Postman. Bạn có thể tải xuống và cài đặt trên trang chủ của nó (https://www.getpostman.com/postman)

#### Tạo user
![anh1](/image/post.png)

#### Get all user
![anh2](/image/getall.png)

#### Get 1 user
![anh3](/image/1user.png)

#### Chỉnh sửa user
![anh4](/image/put.png)

#### Xóa user
![anh5](/image/delete.png)

Như vậy chúng ta đã có thể tạo api với Flask 
