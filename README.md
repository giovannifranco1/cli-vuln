# Vuln

![Python Version](https://img.shields.io/badge/Python-^3.8.0-brightgreen) ![Poetry(https://getcomposer.org/doc/00-intro.md#installation-linux-unix-macos) ](https://img.shields.io/badge/Poetry-^1.2.0-brightgreen) ![by Giovanni](https://img.shields.io/badge/%20by-Giovannni-informational?color=ee564b)

[🛠 Ferramentas](#ferramentas) | [⚙ Instalação](#instalação)

---

## Ferramentas

- Requisitos
  - [Python](https://www.python.org/)
  - [Poetry](https://python-poetry.org/)
  - [Git](https://git-scm.com/downloads)

- Recomendados
  - [Docker](https://www.docker.com/)

---

## Instalação

### Copie o .env.example para .env
```bash
  poetry install
```

## Utilização
```bash
  poetry run cli-start {path_arquivo_ou_diretório_para_escanamento} --vulnerability="{vulnerabilidade_para_escaneamento}"
```


################################################################



## Exemplos de comandos básicos

Escaneamento de vulnerabilidades XSS somente em um arquivo 
```bash
  poetry run cli-start arquivo.php --vulnerability="xss"
```

Escaneamento de vários arquivos
```bash
  poetry run cli-start /home/giovanni/www --vulnerability="xss"
```

################################################################


