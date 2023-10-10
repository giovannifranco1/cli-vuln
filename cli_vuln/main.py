import sys
import os
import typer
import time

from cli_vuln.core.banner import BANNER
from termcolor import colored
from cli_vuln.vulnerabilities.xss import Xss
from cli_vuln.vulnerabilities.sqli import SQLInjection
from rich.progress import track
from typing import Optional
from pathlib import Path
from rich import print
from rich.panel import Panel
from rich.console import Console
from rich.prompt import Prompt
from rich.prompt import Confirm
from typing_extensions import Annotated
from cli_vuln import __version__
from enum import Enum
from cli_vuln.core import utils

app = typer.Typer()


class Vulns(str, Enum):
    xss = "xss"
    sql_injection = "sqli"
    ip_expose = "ip_expose"


@app.command()
def scanner(path: Path, vulnerability: Annotated[Vulns, typer.Option(case_sensitive=False)]):
    print(BANNER)

    vuln_classes = utils.get_vulnerability_classes()
    vulns_list = [(_class.name, _class.keyname) for _class in vuln_classes]

    if path.is_file() and path.suffix.lower() == ".php":
        is_save_log = Confirm.ask("Deseja salvar?")

        with open(path, "r") as arquivo_php:
            # Leia o conteúdo do arquivoblue
            conteudo = arquivo_php.read()

            Vulnerability = [_class for _class in vuln_classes if _class.keyname == vulnerability][0]
            vuln_obj = Vulnerability(path)
            vulns = vuln_obj.find()

            total = len(vulns)
            is_vuln = total > 0
            string_montada = ""

            for value in track(range(100), description="[red]Verificando arquivo ...[/red]"):
                # Fake processing time
                time.sleep(0.01)

            print("")

            # Imprima o conteúdo no console
            for vuln in vulns:
                string_montada += f"[yellow]{vuln[0]}[/yellow] - Linha: [green]{vuln[1]}[/green]\n"

            print(Panel(string_montada, title=f"{total} Vulnerabilidades encontradas", border_style="red"))

            if is_vuln:
                string_montada = ""

                for link in vuln_obj.get_links():
                    string_montada += f"[yellow]{link}\n[/yellow]"

                print(Panel.fit(string_montada, title="Links", border_style="green"))
    else:
        typer.echo(f"O arquivo {path} não existe ou não é um arquivo PHP.")


if __name__ == "__main__":
    app()
