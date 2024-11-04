import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer as SqlInteger, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from spyne import Application, rpc, ServiceBase, Unicode, Iterable, Integer
from spyne.protocol.soap import Soap11
from spyne.server.wsgi import WsgiApplication
from flask import Flask

# Configuração do banco de dados
DATABASE_DIR = "./data"
DATABASE_FILE = f"{DATABASE_DIR}/users.db"
if not os.path.exists(DATABASE_DIR):
    os.makedirs(DATABASE_DIR)
engine = create_engine(f'sqlite:///{DATABASE_FILE}')
Session = sessionmaker(bind=engine)
Base = declarative_base()

# Configurações JWT
SECRET_KEY = "tuna_o_melhor_time_do_norte"
ALGORITHM = "HS256"
TOKEN_EXPIRATION_MINUTES = 120


# Modelo de Usuário
class User(Base):
    __tablename__ = 'users'
    id = Column(SqlInteger, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    mobile_number = Column(String)
    email = Column(String, unique=True, nullable=False)
    company = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    password = Column(String, nullable=False)
    

# Inicialização do banco de dados
def initialize_database():
    if not os.path.exists(DATABASE_FILE):
        Base.metadata.create_all(engine)
        session = Session()
        try:
            hashed_password = bcrypt.hashpw("adm@123".encode('utf-8'), bcrypt.gensalt())
            admin_user = User(username="admin", first_name="Admin", last_name="User",
                              mobile_number="0000000000", email="admin@example.com",
                              company="AdminCorp", password=hashed_password)
            session.add(admin_user)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Erro ao inicializar o banco de dados: {e}")
        finally:
            session.close()


initialize_database()


# Função para criar o token JWT
def create_jwt_token(username):
    expiration = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    payload = {"sub": username, "exp": expiration}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


# Função para verificar o token JWT
def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expirado")
    except jwt.InvalidTokenError:
        raise ValueError("Token inválido")


# Serviço SOAP
class UserService(ServiceBase):
    @rpc(Unicode, Unicode, _returns=Unicode)
    def authenticate_user(ctx, username, password):
        session = Session()
        try:
            user = session.query(User).filter(User.username == username).first()
            if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
                token = create_jwt_token(username)
                return f"Autenticação bem-sucedida. Token: {token}"
            else:
                return "Falha na autenticação"
        finally:
            session.close()

    @staticmethod
    def validate_token(ctx):
        auth_header = ctx.transport.req_env.get('HTTP_AUTHORIZATION')
        if not auth_header:
            raise ValueError("Token não encontrado no cabeçalho Authorization")
        
        token = auth_header.split(" ")[1]  # Extrai o token do cabeçalho 'Bearer <token>'
        return verify_jwt_token(token)

    @rpc(Unicode, Unicode, Unicode, Unicode, Unicode, Unicode, Unicode, _returns=Unicode)
    def add_user(ctx, username, first_name, last_name, mobile_number, email, company, password):
        UserService.validate_token(ctx)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        session = Session()
        try:
            user = User(username=username, first_name=first_name, last_name=last_name,
                        mobile_number=mobile_number, email=email, company=company, password=hashed_password)
            session.add(user)
            session.commit()
            return "Usuário adicionado com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao adicionar usuário: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, Unicode, Unicode, Unicode, Unicode, Unicode, Unicode, _returns=Unicode)
    def update_user(ctx, user_id, first_name, last_name, mobile_number, email, company, password):
        UserService.validate_token(ctx)
        session = Session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return "Usuário não encontrado"
            user.first_name = first_name
            user.last_name = last_name
            user.mobile_number = mobile_number
            user.email = email
            user.company = company
            if password:
                user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            session.commit()
            return "Usuário atualizado com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao atualizar usuário: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, _returns=Unicode)
    def delete_user(ctx, user_id):
        UserService.validate_token(ctx)
        session = Session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return "Usuário não encontrado"
            session.delete(user)
            session.commit()
            return "Usuário excluído com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao excluir usuário: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, _returns=Iterable(Unicode))
    def get_user(ctx, user_id):
        UserService.validate_token(ctx)
        session = Session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                return [user.username, user.first_name, user.last_name, user.mobile_number,
                        user.email, user.company, str(user.created_at)]
            else:
                return ["Usuário não encontrado"]
        finally:
            session.close()

    @rpc(_returns=Iterable(Iterable(Unicode)))
    def list_users(ctx):
        UserService.validate_token(ctx)
        session = Session()
        try:
            users = session.query(User).all()
            return [[user.username, user.first_name, user.last_name, user.mobile_number,
                     user.email, user.company, str(user.created_at)] for user in users]
        finally:
            session.close()
            

# Configuração da aplicação Spyne
soap_app = Application(
    [UserService],
    tns="spyne.examples.userservice",
    in_protocol=Soap11(),
    out_protocol=Soap11()
)

# Configuração do servidor Flask para o WSGI
flask_app = Flask(__name__)
flask_app.wsgi_app = WsgiApplication(soap_app)


@flask_app.route("/")
def home():
    return "Serviço SOAP de Usuários disponível em /soap"


if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=5000)
