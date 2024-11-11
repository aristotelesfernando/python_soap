# Sistema de Gerenciamento de Usuários e Grupos - API SOAP

## 🚀 Tecnologias Utilizadas

### Linguagem Principal
- Python 3.x

### Bibliotecas Principais
- **Flask**: Framework web leve e flexível
- **Spyne**: Framework para criação de serviços SOAP
- **SQLAlchemy**: ORM (Object Relational Mapper) para Python
- **PyJWT**: Implementação do JSON Web Token
- **BCrypt**: Biblioteca para hash de senhas
- **WSGI**: Interface para comunicação entre servidor web e aplicações Python

### Containerização
- **Docker**: Plataforma de containerização
- **Docker Compose**: Orquestrador de containers

## 📁 Estrutura do Projeto
```
.
├── app/
│   ├── data/
│   │   └── users.db        # Banco de dados SQLite
│   └── app.py             # Arquivo principal da aplicação
├── Dockerfile            # Configuração do container da aplicação
├── docker-compose.yml    # Configuração dos serviços
└── requirements.txt      # Dependências do projeto
```


## 💾 Banco de Dados

### Sistema Gerenciador (SGBD)
- SQLite3
- Localização: `/app/data/users.db`
- Criação automática na primeira execução

### Estrutura de Tabelas

#### Tabela `users`
| Campo         | Tipo     | Descrição               |
| ------------- | -------- | ----------------------- |
| id            | Integer  | Chave primária          |
| username      | String   | Nome de usuário (único) |
| first_name    | String   | Primeiro nome           |
| last_name     | String   | Sobrenome               |
| mobile_number | String   | Número de telefone      |
| email         | String   | Email (único)           |
| company       | String   | Empresa                 |
| created_at    | DateTime | Data de criação         |
| password      | String   | Senha (hash bcrypt)     |

#### Tabela `groups`
| Campo      | Tipo    | Descrição             |
| ---------- | ------- | --------------------- |
| id         | Integer | Chave primária        |
| group_name | String  | Nome do grupo (único) |

#### Tabela `user_groups`
| Campo    | Tipo    | Descrição                     |
| -------- | ------- | ----------------------------- |
| id_user  | Integer | Chave estrangeira (users.id)  |
| id_group | Integer | Chave estrangeira (groups.id) |

### Usuário Administrador Padrão
- Username: `admin`
- Senha: `adm@123`
- Grupo: `SYSTEM`
- Este usuário é criado automaticamente na primeira execução

## 🔐 Autenticação e Segurança

### JWT (JSON Web Token)
- Tempo de expiração: 120 minutos
- Gerado no login bem-sucedido
- Requerido para todas as operações (exceto autenticação)

### Formato do Token
- Header: `Authorization: Bearer <token>`

### Processo de Autenticação
1. Cliente envia credenciais (username/password)
2. Sistema valida credenciais
3. Se válido, retorna token JWT
4. Token deve ser incluído em todas requisições subsequentes

## 🚀 Instalação e Execução

### Usando Docker (Recomendado)

1. Clone o repositório
```bash
git clone <repository-url>
```

2. Construa e inicie os containers
```bash
docker-compose up -d --build
```

3. Verifique os logs (opcional)
```bash
docker-compose logs -f
```

4. Para parar os containers
```bash
docker-compose down
```

### Instalação Manual (Alternativa)

1. Clone o repositório
```bash
git clone <repository-url>
```

2. Crie um ambiente virtual
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Instale as dependências
```bash
pip install -r requirements.txt
```

4. Execute a aplicação
```bash
python app.py
```

O servidor será iniciado em `http://localhost:5000`

## 📝 Exemplos de Requisições SOAP

### Autenticação (authenticate_user)
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="spyne.examples.userservice">
   <soapenv:Header/>
   <soapenv:Body>
      <user:authenticate_user>
         <user:username>admin</user:username>
         <user:password>adm@123</user:password>
      </user:authenticate_user>
   </soapenv:Body>
</soapenv:Envelope>
```

### Criar Novo Usuário (add_user)
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="spyne.examples.userservice">
   <soapenv:Header>
      <Authorization>Bearer {seu-token-jwt}</Authorization>
   </soapenv:Header>
   <soapenv:Body>
      <user:add_user>
         <user:username>joao.silva</user:username>
         <user:first_name>João</user:first_name>
         <user:last_name>Silva</user:last_name>
         <user:mobile_number>11999999999</user:mobile_number>
         <user:email>joao.silva@example.com</user:email>
         <user:company>Empresa XYZ</user:company>
         <user:password>senha123</user:password>
      </user:add_user>
   </soapenv:Body>
</soapenv:Envelope>
```

### Criar Novo Grupo (add_group)
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="spyne.examples.userservice">
   <soapenv:Header>
      <Authorization>Bearer {seu-token-jwt}</Authorization>
   </soapenv:Header>
   <soapenv:Body>
      <user:add_group>
         <user:group_name>Vendas</user:group_name>
      </user:add_group>
   </soapenv:Body>
</soapenv:Envelope>
```

### Adicionar Usuário ao Grupo (add_user_to_group)
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="spyne.examples.userservice">
   <soapenv:Header>
      <Authorization>Bearer {seu-token-jwt}</Authorization>
   </soapenv:Header>
   <soapenv:Body>
      <user:add_user_to_group>
         <user:user_id>2</user:user_id>
         <user:group_id>1</user:group_id>
      </user:add_user_to_group>
   </soapenv:Body>
</soapenv:Envelope>
```

### Listar Usuários (list_users)
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="spyne.examples.userservice">
   <soapenv:Header>
      <Authorization>Bearer {seu-token-jwt}</Authorization>
   </soapenv:Header>
   <soapenv:Body>
      <user:list_users/>
   </soapenv:Body>
</soapenv:Envelope>
```

### Listar Usuários de um Grupo (list_users_in_group)
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="spyne.examples.userservice">
   <soapenv:Header>
      <Authorization>Bearer {seu-token-jwt}</Authorization>
   </soapenv:Header>
   <soapenv:Body>
      <user:list_users_in_group>
         <user:group_id>1</user:group_id>
      </user:list_users_in_group>
   </soapenv:Body>
</soapenv:Envelope>
```

## 📝 Notas Importantes

- Todas as senhas são armazenadas com hash BCrypt
- O banco de dados é criado automaticamente no primeiro uso
- O grupo SYSTEM e usuário admin são criados automaticamente
- Todas as operações (exceto autenticação) requerem token JWT válido
- O servidor SOAP está disponível em `/soap`

## 🔒 Recomendações de Segurança

1. Altere a senha do usuário admin após a primeira execução
2. Modifique a SECRET_KEY em ambiente de produção
3. Configure HTTPS em ambiente de produção
4. Implemente política de renovação de tokens
5. Mantenha as dependências atualizadas
6. Em ambiente de produção, considere usar um banco de dados mais robusto como PostgreSQL
7. Configure limites de requisições (rate limiting)
8. Implemente monitoramento e logging

## 🛠 Testes das Requisições

Para testar as requisições SOAP, você pode usar:
- SoapUI
- Postman (com raw XML)
- cURL

Exemplo de teste com cURL:
```bash
curl -X POST \
  http://localhost:5000/soap \
  -H 'Content-Type: text/xml' \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="spyne.examples.userservice">
   <soapenv:Header/>
   <soapenv:Body>
      <user:authenticate_user>
         <user:username>admin</user:username>
         <user:password>adm@123</user:password>
      </user:authenticate_user>
   </soapenv:Body>
</soapenv:Envelope>'
```