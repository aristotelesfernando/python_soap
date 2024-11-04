```markdown
# Projeto: Serviço SOAP de Gerenciamento de Usuários com Autenticação JWT

## Visão Geral
Este projeto implementa um serviço SOAP para gerenciar dados de usuários, permitindo operações de autenticação, criação, atualização, exclusão e consulta de usuários. A autenticação é realizada via JWT, e cada solicitação deve conter um token válido para que seja executada. O banco de dados utilizado é SQLite, e a estrutura do banco de dados é inicializada automaticamente, criando um usuário administrador padrão na primeira execução.

## Tecnologias Utilizadas
- **Python 3.10** ou superior
- **Flask** para gerenciamento do servidor
- **Spyne** para criar serviços SOAP
- **SQLAlchemy** para operações de banco de dados
- **JWT (Json Web Token)** para autenticação
- **bcrypt** para hashing seguro de senhas
- **SQLite** para armazenamento de dados
- **Docker** e **Docker Compose** (opcional) para deploy

## Estrutura de Pastas

```plaintext
.
├── app/
│   ├── user_service.py   # Código do serviço SOAP
│   ├── Dockerfile        # Arquivo para criação da imagem Docker
│   ├── docker-compose.yml # Arquivo de configuração do Docker Compose
├── data/                 # Diretório para armazenamento do banco de dados SQLite
└── README.md             # Documentação do projeto
```

## Inicialização do Banco de Dados
Na primeira execução, o banco de dados será criado automaticamente na pasta `data/` com um usuário `admin` padrão:
- **Usuário**: `admin`
- **Senha**: `adm@123` (hash seguro via `bcrypt`)

## Endpoints Disponíveis

### Rota Base
| Método | Endpoint | Descrição                                             |
| ------ | -------- | ----------------------------------------------------- |
| GET    | `/`      | Rota base que confirma que o serviço está disponível. |

### Métodos SOAP
Todos os métodos SOAP abaixo estão disponíveis no endpoint `/soap`.

| Método              | Descrição                                                                | Parâmetros                                                                             | Retorno                              |
| ------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | ------------------------------------ |
| `authenticate_user` | Autentica um usuário e retorna um token JWT.                             | `username`, `password`                                                                 | Token JWT ou mensagem de erro        |
| `add_user`          | Adiciona um novo usuário ao sistema. Necessita de token válido.          | `username`, `first_name`, `last_name`, `mobile_number`, `email`, `company`, `password` | Mensagem de sucesso ou erro          |
| `update_user`       | Atualiza os dados de um usuário específico. Necessita de token válido.   | `user_id`, `first_name`, `last_name`, `mobile_number`, `email`, `company`, `password`  | Mensagem de sucesso ou erro          |
| `delete_user`       | Exclui um usuário específico. Necessita de token válido.                 | `user_id`                                                                              | Mensagem de sucesso ou erro          |
| `get_user`          | Retorna informações de um usuário específico. Necessita de token válido. | `user_id`                                                                              | Dados do usuário ou mensagem de erro |
| `list_users`        | Lista todos os usuários cadastrados. Necessita de token válido.          | Nenhum                                                                                 | Lista de dados dos usuários          |

## Instalação e Configuração

### Pré-requisitos
Certifique-se de ter o Python 3.10+ e Docker (opcional) instalados.

### Configuração de Ambiente

1. Clone o repositório:
   ```bash
   git clone <URL-do-repositório>
   cd <diretório-do-projeto>
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

### Executando a Aplicação Localmente

Para iniciar o servidor, execute:
```bash
python app/user_service.py
```
A aplicação estará disponível em `http://localhost:5000/`.

### Executando a Aplicação com Docker

#### Build da Imagem Docker

Para criar a imagem Docker, execute:
```bash
docker build -t user-soap-service .
```

#### Utilizando Docker Compose
1. Inicie o serviço:
   ```bash
   docker-compose up -d
   ```
2. O serviço estará disponível em `http://localhost:5000/`.

## Autenticação via JWT

Para acessar os métodos `add_user`, `update_user`, `delete_user`, `get_user` e `list_users`, é necessário fornecer o token JWT obtido pelo método `authenticate_user`.

### Usando o SoapUI para Enviar o Token JWT

1. No SoapUI, configure o cabeçalho `Authorization` com o valor: `Bearer <seu_token_jwt>`.
2. Envie a requisição para o método desejado.

## Exemplo de Requisição SOAP

### Exemplo `authenticate_user`

#### Requisição

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:usr="spyne.examples.userservice">
   <soapenv:Header/>
   <soapenv:Body>
      <usr:authenticate_user>
         <usr:username>admin</usr:username>
         <usr:password>adm@123</usr:password>
      </usr:authenticate_user>
   </soapenv:Body>
</soapenv:Envelope>
```

#### Resposta (com Token JWT)

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <authenticate_userResponse>
         <authenticate_userResult>Autenticação bem-sucedida. Token: <token_jwt></authenticate_userResult>
      </authenticate_userResponse>
   </soapenv:Body>
</soapenv:Envelope>
```

## Licença
Este projeto é distribuído sob a licença MIT.
```

Essa documentação fornece uma visão geral completa do projeto, desde sua execução até como realizar chamadas autenticadas com o SoapUI.