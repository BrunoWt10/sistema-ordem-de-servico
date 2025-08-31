# Sistema de Gerenciamento de Ordens de Serviço (OS)

Este é um sistema de gerenciamento de ordens de serviço completo, desenvolvido em **Python** com o framework **Flask**. O projeto foi concebido para atender às necessidades de uma assistência técnica ou empresa de reparos, permitindo o registro, acompanhamento e a gestão de clientes, serviços e ordens de serviço de forma eficiente.

A aplicação oferece um painel de controle administrativo para gerenciar usuários, clientes e serviços, garantindo que a operação seja escalável e segura. O uso de bancos de dados relacionais e um sistema de autenticação de usuários com papéis distintos demonstra uma sólida compreensão de boas práticas de desenvolvimento.

## Tecnologias Utilizadas
* **Back-end:** Python, Flask
* **Banco de Dados:** SQLAlchemy (SQLite)
* **Segurança:** Flask-Bcrypt (para hash de senhas) e Flask-Login (para gerenciamento de sessões de usuário)
* **Formulários:** Flask-WTF e WTForms
* **E-mail:** Flask-Mail

## Funcionalidades Principais
* **Gerenciamento de Ordens de Serviço (OS):** Criação, edição, visualização e acompanhamento de OSs, com campos para descrição, status (aberta, em andamento, concluída), prioridade e atribuição a técnicos específicos.
* **Cadastro e Gestão de Clientes:** Módulo para adicionar, remover e editar clientes.
* **Registro e Controle de Serviços:** Gerenciamento dos tipos de serviços oferecidos, incluindo nome, descrição e preço.
* **Sistema de Usuários e Papéis:** Múltiplos usuários podem acessar o sistema com diferentes níveis de permissão (`admin` e `técnico`), garantindo controle de acesso a funcionalidades sensíveis.
* **Geração de Faturas/Recibos:** Funcionalidade para criar faturas vinculadas às ordens de serviço, com controle de valor total e status de pagamento.
* **Painel de Controle:** Uma dashboard inicial que fornece uma visão geral das últimas OSs e um resumo das atividades.

## Como Executar o Projeto

1.  **Clone o repositório:**
    `git clone https://github.com/BrunoWt10/sistema-ordem-de-servico.git`
2.  **Instale as dependências:**
    `pip install -r requirements.txt`
3.  **Execute o servidor:**
    `python app.py`

O projeto estará disponível em `http://127.0.0.1:5000`.

---

Agora que você tem os arquivos completos, a sua missão é fazer o `commit` e o `push` para subir as alterações. Em seguida, o seu portfólio e o seu projeto estarão com a melhor apresentação possível.
