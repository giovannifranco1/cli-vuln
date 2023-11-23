import sys
import os
import typer
import time
import tempfile

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

# Variáveis globais
vulns_global = []


class Vulns(str, Enum):
    xss = "xss"
    sql_injection = "sqli"
    ip_expose = "ip_expose"


"""
    CLI para encontrar vulnerabilidades em arquivos PHP utilizando REGEX
    
    return: None
"""


@app.command()
def scan_php(path: Path, vulnerability: Annotated[Vulns, typer.Option(case_sensitive=False)]):
    print(BANNER)

    vuln_classes = utils.get_vulnerability_classes()
    vulns_list = [(_class.name, _class.keyname) for _class in vuln_classes]

    if not path.exists():
        print(f"[red]The file or directory does not exist.[/red]")
        raise typer.Exit(code=1)

    if path.is_dir():
        is_save_log = Confirm.ask("Do you want to save?")
        if is_save_log:
            path_log = Prompt.ask("Enter the path to save the log", default="log.txt")
            path_log = Path(path_log)

        print(f"[yellow]Checking files in the directory {path} ...[/yellow]")
        print("")

        Vulnerability = [_class for _class in vuln_classes if _class.keyname == vulnerability][0]
        files = path.glob("**/*.php")

        for _path in track(
            path.glob("**/*.php"),
            description="[red]Checking files ...[/red]",
            total=len(list(files)),
            complete_style="green",
            finished_style="green",
        ):
            if _path.is_dir():
                continue

            time.sleep(0.02)

            print(f"[yellow]Checking file {_path} ...[/yellow]")

            with open(_path, "r", encoding="iso-8859-1") as arquivo_php:
                vuln_obj = Vulnerability(_path)  # Instancie a classe de vulnerabilidade
                vulns = vuln_obj.find()  # Vulnerabilidades encontradas

                if vulns:
                    print(f"[red]🐛 Vulnerabilities found in the file {_path}[/red]")
                    vulns = [vulns[0] + (_path,)]  # Adicione o path do arquivo na tupla
                    vulns_global.append(vulns)  # Adicione as vulnerabilidades encontradas na lista global

    if path.is_file() and path.suffix.lower() == ".php":
        is_save_log = Confirm.ask("Deseja salvar?")

        with open(path, "r") as arquivo_php:
            Vulnerability = [_class for _class in vuln_classes if _class.keyname == vulnerability][0]
            vuln_obj = Vulnerability(path)
            vulns = vuln_obj.find()

            if vulns:
                print(f"[green]:bug:[/green] [red]Vulnerabilities found in the file {path}[/red]")
                vulns = [vulns[0] + (path,)]
                vulns_global.append(vulns)

            for value in track(
                range(100), description="[red]Checking file ...[/red]", total=100, complete_style="green", finished_style="green"
            ):
                # Fake processing time
                time.sleep(0.01)

            print("")

    total = len(vulns_global)
    is_vuln = total > 0
    string_lines_vulnerabilities_mounted = ""

    for vulns in vulns_global:
        for vuln in vulns:
            string_lines_vulnerabilities_mounted += (
                f'[yellow]{vuln[0]}[/yellow] - Line: [green]{vuln[1]}[/green] | "[yellow]{vuln[3]}[/yellow]" \n'
            )

    print("")
    print(Panel(string_lines_vulnerabilities_mounted, title=f"{total} Vulnerabilities found", border_style="red"))

    if is_vuln:
        string_lines_lins_mounted = ""

        for link in vuln_obj.get_links():
            string_lines_lins_mounted += f"[yellow]{link}\n[/yellow]"

        print(Panel(string_lines_lins_mounted, title="Links", border_style="green"))

    if is_save_log:
        print(f"[yellow]Saving log in {path_log} ...[/yellow]")

        string_lines_log_mounted = f"Vulnerabilities found in {path}:\n\n"

        for vulns in vulns_global:
            for vuln in vulns:
                string_lines_log_mounted += f"{vuln[0]} - Line: {vuln[1]} | {vuln[3]}\n"

        if path_log.is_dir():
            path = path_log / "log.txt"
            path_log = path

        with open(path_log, "w") as log_file:
            if not is_vuln:
                log_file.write("No vulnerabilities found.\n")
            else:
                log_file.write(string_lines_log_mounted)


if __name__ == "__main__":
    app()
