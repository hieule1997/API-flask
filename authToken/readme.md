# API Flask với tokenauth
## 1.Cài đặt các gói 
Cài đặt các gói cần thiết 
```
pip install flask flask-restful flask-jwt-extended passlib flask-sqlalchemy
```
## 2.Cài đặt viết các API 

Tạo 1 file views.py

```
from run import app
from flask import jsonify
@app.route('/')
def index():
    return jsonify({'message': 'Hello, World!'})
```

Tạo file resources.py   
File này viết các API đưa ra các thông tin 
```
from flask_restful import Resource

class UserRegistration(Resource):
    def post(self):
        return {'message': 'User registration'}


class UserLogin(Resource):
    def post(self):
        return {'message': 'User login'}
      
      
class UserLogoutAccess(Resource):
    def post(self):
        return {'message': 'User logout'}
      
      
class UserLogoutRefresh(Resource):
    def post(self):
        return {'message': 'User logout'}
      
      
class TokenRefresh(Resource):
    def post(self):
        return {'message': 'Token refresh'}
      
      
class AllUsers(Resource):
    def get(self):
        return {'message': 'List of users'}

    def delete(self):
        return {'message': 'Delete all users'}
      
      
class SecretResource(Resource):
    def get(self):
        return {
            'answer': 42
        }
      
```
Chúng ta đã tạo ra 7 resource bao gồm 
* Đăng kí và đăng nhập user
* Đăng xuất 
* refresh token 
* token refresh
* Liệt kê list các user
* Hàm bí mật

Sau đó add các hàm này cho nó 1 Url trong file run.py

```
rom flask import Flask
from flask_restful import Api

app = Flask(__name__)
api = Api(app)

import views, models, resources

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.SecretResource, '/secret')
```


cần thêm đoạn code vào resources.py

```
from flask_restful import Resource, reqparse

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)
```

Chúng ta sử dụng reqparse để khởi tạo các biến có thể sử dụng trong các hàm còn lại. Ví dụ như đoạn code sau đây

```
class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        return data


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        return data
```

## Đăng kí và đăng nhập user 

### Chúng ta cần phải tạo database 
Ở đây chúng ta sử dụng SQLite bạn cũng có thể sử dụng Mysql hoặc PostgreSQL. Mở file run.py và thêm đoạn code sau :
```
from flask_sqlalchemy import SQLAlchemy

...

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'

db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

```
Đây là đoạn code khởi tạo và cấu hình database. Hàm create_table() là để tạo database


Tiếp theo chúng ta tạo một file models.py   
```
from run import db

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
```

ở đây chúng ta đã kết nối với db.giờ chúng ta sẽ làm việc với database.   
Viết lại hàm UserRegistration trong resourecs.py như sau :
```

from models import UserModel


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        new_user = UserModel(
            username = data['username'],
            password = data['password']
        )
        try:
            new_user.save_to_db()
            return {
                'message': 'User {} was created'.format( data['username'])
            }
        except:
            return {'message': 'Something went wrong'}, 500
```
Sử dụng hàm save_to_db() để lưu username , password 
 khi có ngoại lệ sảy ra thì sẽ đi vào except vào báo lỗi 
   
Khi một người dùng đã đăng kí với username đã tồn tại thì chúng ta thông báo cho họ. Vậy làm sao có thể làm được như vậy chúng ta cần phải thêm 1 đoạn code ckeck user đã được đăng kí hay chưa. Thêm đoạn code dưới đây trong hàm `UserModel` class in models.py
```
@classmethod
def find_by_username(cls, username):
   return cls.query.filter_by(username = username).first()
```

Hàm đăng kí thành như sau :
```
class UserRegistration(Resource):
    def post(self):
      data = parser.parse_args()

      if UserModel.find_by_username(data['username']):
          return {'message': 'User {} already exists'. format(data['username'])}

      new_user = ...
```


Tiếp theo là hàm Login :

```
class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        
        if data['password'] == current_user.password:
            return {'message': 'Logged in as {}'.format(current_user.username)}
        else:
            return {'message': 'Wrong credentials'}
```
Đầu tiên chúng ta phân tích các yêu cầu cùng các tham số được truyền vào kiểm tra xem username đó đã tồn tại hay chưa. 
Check password có đúng hay không ?
  
Nếu password đã đúng chúng ta show ra thông báo đăng nhập đã thành công còn không thì báo lỗi 

Get all user 

Chúng ta muốn lấy tất cả thông tin user 
```
class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()
```
Để có hàm return_all() và delete_all() chúng ta cần phải có trong UserModel

```
@classmethod
def return_all(cls):
    def to_json(x):
        return {
            'username': x.username,
            'password': x.password
        }
    return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

@classmethod
def delete_all(cls):
    try:
        num_rows_deleted = db.session.query(cls).delete()
        db.session.commit()
        return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
    except:
        return {'message': 'Something went wrong'}
```

để đảm bảo về bảo mật thông tin chúng ta nên mã hóa mật khẩu . Để làm được chúng ta cần thêm đoạn code sau :
```
from passlib.hash import pbkdf2_sha256 as sha256
class UserModel(db.Model):
    ...
    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)
```
Hàm generate_hash() để chuyển đổi password sang mã hóa sha256  
Hàm  verify_hash() so sánh password với mã đã được mã hóa  
Như vậy chúng ta cần chỉnh sửa lại một số code bên trong hàm đăng kí, đăng nhập  
Trong hàm đăng kí
```
new_user = UserModel(
    username = data['username'],
    password = UserModel.generate_hash(data['password'])
)
```
Trong hàm đăng nhập  
```
if UserModel.verify_hash(data['password'], current_user.password):
    ...
else:
    ...
```

## 4.Thêm JWT 
JWT là viết tắt của từ Json Web Token 
Bắt đầu với run.py  :
```
from flask_jwt_extended import JWTManager
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)
```

Đầu tiên ta import JWTManager từ flask_jwt_extended 

Nhập config JWT_SECRET_KEY Với jwt-secret-string

cuối cùng khởi tạo 1 thể hiện jwt trong class JWTManager

Tiếp theo bạn cần
```
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
```
ở đây chúng ta cần thay đổi lại đăng nhập, đăng kí để có thể nhận được token khi đăng nhập đăng kí. Đoạn mã được viết lại như sau 

```
class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}
        
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}
```
Chúng ta sử dụng hàm create_access_token() với tham số đầu vào là một identity . chúng sẽ tạo cho ta một token. còn hàm create_refresh_token () sẽ tạo một token khác dự phòng khi mà token chính bị hết hạn 

Để bảo vệ tài nguyên chúng ta chỉ cần thêm `@jwt_required` vì vậy khi đó bạn cần phải có token mới có thể lấy tài nguyên. Việc sử dụng `@jwt_required ` Tùy vào cách sử lý của tài nguyên.
Ví dụ :

```
class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }
```


Mã token có thời gian hết hạn. Theo mặc định thì token sẽ có 15 phút còn token_refresh sẽ có thời gian là 30 ngày.

## 5. Đăng xuất và thu hồi token

Sau đây là cách đơn giản nhất để đăng xuất:
trong models.py thêm đoạn code 
```
class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))
    
    def add(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)
```
Hàm is_jti_backlisted cos tác dụng kiểm tra xem token có bị thu hồi chưa 

Tiếp thêm 1 đoạn code sau : 
```
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)
```
Đầu tiên là cho phép JWT_BACKLIST_ENABLED. Sau đó cấp quyền truy cập và làm mới 
Tiếp theo bạn có thể thấy hàm check_if_token_in_blacklist() với @jwt.token_in_blacklist_loader nó sẽ trả về true hay flase tùy thuộc token nằm trong backlist

Đăng xuất  trong resuocres.py
from models import UserModel, RevokedTokenModel
```
class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500
```
Bởi vì chúng tôi có 2 token , và token refresh vì vậy sẽ có 2 hàm  đăng xuất cho mỗi token.chúng tôi sẽ RevokedTokenModel 


## Lưu ý : 

Bạn có thể config thời gian hết hạn của token với :  ` app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=1800)`