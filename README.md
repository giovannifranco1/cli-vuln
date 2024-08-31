# Vuln
CLI para escaneamento de vulnerabilidades em arquivos PHP

Bom dia, boa tarde e boa noite! Seja bem-vindo ao Vuln, um CLI para escaneamento de vulnerabilidades em arquivos PHP. Este projeto foi desenvolvido com o intuito de facilitar a vida de desenvolvedores que desejam escanear seus arquivos PHP em busca de vulnerabilidades XSS, SQL Injection e IP Address.

Ele foi desenvolvido com Python hehe, e utiliza o framework Typer para criação de comandos CLI. Ele esta em uma versão inicial, então sinta-se a vontade para contribuir com o projeto. Beijos e abraços!

![Python Version](https://img.shields.io/badge/Python-^3.8.0-brightgreen) ![Poetry(https://getcomposer.org/doc/00-intro.md#installation-linux-unix-macos) ](https://img.shields.io/badge/Poetry-^1.2.0-brightgreen) ![by Giovanni](https://img.shields.io/badge/%20by-Giovanni-informational?color=ee564b)

[🛠 Ferramentas](#ferramentas) | [⚙ Instalação](#instalação)

## Ferramentas

- Requisitos
  - [Python](https://www.python.org/)
  - [Poetry](https://python-poetry.org/)
  - [Git](https://git-scm.com/downloads)

- Recomendados
  - [Docker](https://www.docker.com/)

---

## Features
- [x] Escaneamento de vulnerabilidades XSS
- [x] Escaneamento de vulnerabilidades SQL Injection
- [x] Escaneamento de vulnerabilidades IP Address

## Instalação
1. Clone o repositório
```bash
  git clone 
```
2. Instale as dependências
```bash
  poetry install
```
3. Crie um arquivo .env
```bash
  cp .env.example .env
```
4. Execute o comando
```bash
  poetry run cli-start {path_arquivo_ou_diretório_para_escanamento} --vulnerability="{vulnerabilidade_para_escaneamento}"
```
5. Aproveite! 🚀


## Exemplos de comandos básicos

Escaneamento de vulnerabilidades XSS somente em um arquivo 
```bash
  poetry run cli-start arquivo.php --vulnerability="xss"
```

Escaneamento de vários arquivos
```bash
  poetry run cli-start {path_arquivo_ou_diretório_para_escanamento} --vulnerability="xss"
```

Adicionar um modelo de vulnerabilidade
```bash
  poetry run cli-start new-model {path_model}
```


