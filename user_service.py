import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer as SqlInteger, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
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

# Modelo de Grupo


class Group(Base):
    __tablename__ = 'groups'
    id = Column(SqlInteger, primary_key=True)
    group_name = Column(String, unique=True, nullable=False)
    users = relationship('User', secondary='user_groups')

# Modelo de UserGroup (tabela de relacionamento)


class UserGroup(Base):
    __tablename__ = 'user_groups'
    id_user = Column(SqlInteger, ForeignKey('users.id'), primary_key=True)
    id_group = Column(SqlInteger, ForeignKey('groups.id'), primary_key=True)

# Modelo de Usuário (atualizado com relationship)


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
    groups = relationship('Group', secondary='user_groups')

# Inicialização do banco de dados


def initialize_database():
    if not os.path.exists(DATABASE_FILE):
        Base.metadata.create_all(engine)
        session = Session()
        try:
            # Criar usuário admin
            hashed_password = bcrypt.hashpw(
                "adm@123".encode('utf-8'), bcrypt.gensalt())
            admin_user = User(username="admin", first_name="Admin", last_name="User",
                              mobile_number="0000000000", email="admin@example.com",
                              company="AdminCorp", password=hashed_password)
            session.add(admin_user)
            session.flush()  # Para obter o ID do admin_user

            # Criar grupo SYSTEM
            system_group = Group(group_name="SYSTEM")
            session.add(system_group)
            session.flush()  # Para obter o ID do system_group

            # Relacionar admin ao grupo SYSTEM
            user_group = UserGroup(id_user=admin_user.id,
                                   id_group=system_group.id)
            session.add(user_group)

            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Erro ao inicializar o banco de dados: {e}")
        finally:
            session.close()

# [Funções JWT existentes permanecem iguais]


def create_jwt_token(username):
    expiration = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    payload = {"sub": username, "exp": expiration}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expirado")
    except jwt.InvalidTokenError:
        raise ValueError("Token inválido")

# Serviço SOAP atualizado


class UserService(ServiceBase):
    @rpc(Unicode, Unicode, _returns=Unicode)
    def authenticate_user(ctx, username, password):
        session = Session()
        try:
            user = session.query(User).filter(
                User.username == username).first()
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

        # Extrai o token do cabeçalho 'Bearer <token>'
        token = auth_header.split(" ")[1]
        return verify_jwt_token(token)

    @rpc(Unicode, Unicode, Unicode, Unicode, Unicode, Unicode, Unicode, _returns=Unicode)
    def add_user(ctx, username, first_name, last_name, mobile_number, email, company, password):
        UserService.validate_token(ctx)
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
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
                user.password = bcrypt.hashpw(
                    password.encode('utf-8'), bcrypt.gensalt())
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

    # Novos métodos para gerenciamento de grupos

    @rpc(Unicode, _returns=Unicode)
    def add_group(ctx, group_name):
        UserService.validate_token(ctx)
        session = Session()
        try:
            group = Group(group_name=group_name)
            session.add(group)
            session.commit()
            return "Grupo adicionado com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao adicionar grupo: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, Unicode, _returns=Unicode)
    def update_group(ctx, group_id, new_group_name):
        UserService.validate_token(ctx)
        session = Session()
        try:
            group = session.query(Group).filter(Group.id == group_id).first()
            if not group:
                return "Grupo não encontrado"
            group.group_name = new_group_name
            session.commit()
            return "Grupo atualizado com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao atualizar grupo: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, _returns=Unicode)
    def delete_group(ctx, group_id):
        UserService.validate_token(ctx)
        session = Session()
        try:
            group = session.query(Group).filter(Group.id == group_id).first()
            if not group:
                return "Grupo não encontrado"

            # Verificar se existem usuários no grupo
            user_count = session.query(UserGroup).filter(
                UserGroup.id_group == group_id).count()
            if user_count > 0:
                return "Não é possível deletar o grupo pois existem usuários associados"

            session.delete(group)
            session.commit()
            return "Grupo deletado com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao deletar grupo: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, _returns=Iterable(Unicode))
    def get_group(ctx, group_id):
        UserService.validate_token(ctx)
        session = Session()
        try:
            group = session.query(Group).filter(Group.id == group_id).first()
            if group:
                return [str(group.id), group.group_name]
            else:
                return ["Grupo não encontrado"]
        finally:
            session.close()

    @rpc(_returns=Iterable(Iterable(Unicode)))
    def list_groups(ctx):
        UserService.validate_token(ctx)
        session = Session()
        try:
            groups = session.query(Group).all()
            return [[str(group.id), group.group_name] for group in groups]
        finally:
            session.close()

    # Métodos para gerenciamento de UserGroups
    @rpc(Integer, Integer, _returns=Unicode)
    def add_user_to_group(ctx, user_id, group_id):
        UserService.validate_token(ctx)
        session = Session()
        try:
            # Verificar se usuário e grupo existem
            user = session.query(User).filter(User.id == user_id).first()
            group = session.query(Group).filter(Group.id == group_id).first()

            if not user or not group:
                return "Usuário ou grupo não encontrado"

            # Verificar se já existe a relação
            existing = session.query(UserGroup).filter(
                UserGroup.id_user == user_id,
                UserGroup.id_group == group_id
            ).first()

            if existing:
                return "Usuário já pertence a este grupo"

            user_group = UserGroup(id_user=user_id, id_group=group_id)
            session.add(user_group)
            session.commit()
            return "Usuário adicionado ao grupo com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao adicionar usuário ao grupo: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, Integer, _returns=Unicode)
    def remove_user_from_group(ctx, user_id, group_id):
        UserService.validate_token(ctx)
        session = Session()
        try:
            user_group = session.query(UserGroup).filter(
                UserGroup.id_user == user_id,
                UserGroup.id_group == group_id
            ).first()

            if not user_group:
                return "Relação usuário-grupo não encontrada"

            session.delete(user_group)
            session.commit()
            return "Usuário removido do grupo com sucesso!"
        except Exception as e:
            session.rollback()
            return f"Erro ao remover usuário do grupo: {str(e)}"
        finally:
            session.close()

    @rpc(Integer, _returns=Iterable(Iterable(Unicode)))
    def list_users_in_group(ctx, group_id):
        UserService.validate_token(ctx)
        session = Session()
        try:
            users = session.query(User).join(UserGroup).filter(
                UserGroup.id_group == group_id
            ).all()

            return [[str(user.id), user.username, user.first_name, user.last_name,
                    user.email, user.company] for user in users]
        finally:
            session.close()


# [Configuração da aplicação Flask/SOAP permanece igual]
soap_app = Application(
    [UserService],
    tns="spyne.examples.userservice",
    in_protocol=Soap11(),
    out_protocol=Soap11()
)

flask_app = Flask(__name__)
flask_app.wsgi_app = WsgiApplication(soap_app)


@flask_app.route("/")
def home():
    return "Serviço SOAP de Usuários disponível em /soap"


if __name__ == "__main__":
    initialize_database()
    flask_app.run(host="0.0.0.0", port=5000)
