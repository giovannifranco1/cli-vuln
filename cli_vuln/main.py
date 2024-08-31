import sys
import os
import typer
import time
import tempfile
import pandas as pd
import joblib
import logging
import threading


from time import sleep
from typing import List, Tuple
from rich.live import Live
from datetime import datetime
from cli_vuln.core.banner import BANNER
from termcolor import colored
from cli_vuln.vulnerabilities.xss import Xss
from cli_vuln.vulnerabilities.sqli import SQLInjection
from rich.progress import track
from typing import Optional
from rich.text import Text
from rich.filesize import decimal
from rich.markup import escape
from pathlib import Path
from rich import print
from rich import box
from rich.panel import Panel
from rich.console import Console, Group
from rich.prompt import Prompt
from rich.prompt import Confirm
from typing_extensions import Annotated
from cli_vuln import __version__
from enum import Enum
from cli_vuln.core import utils
from cli_vuln.core.security import model_utils
from cli_vuln.core.security import scanning_utils
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn, BarColumn, Task
from rich.layout import Layout
from rich.table import Table, Row, Style
from rich.syntax import Syntax
from rich.align import Align
from cli_vuln.common.abc import Vulnerability
from concurrent.futures import ThreadPoolExecutor
from rich.tree import Tree
from rich.logging import RichHandler
from readchar import readkey, key

app = typer.Typer(help="CLI for finding vulnerabilities in PHP files using REGEX and Machine Learning")

# Variables globais
vulns_global = []
predictions_global = []
log_scan_full = Table.grid(padding=1)


def make_sponsor_message() -> Panel:
    """Some example content."""
    sponsor_message = Table.grid(padding=1)
    sponsor_message.add_column(style="green", justify="right")
    sponsor_message.add_column(no_wrap=True)
    sponsor_message.add_row(
        "Twitter",
        "[u blue link=https://twitter.com/textualize]https://twitter.com/textualize",
    )
    sponsor_message.add_row(
        "CEO",
        "[u blue link=https://twitter.com/willmcgugan]https://twitter.com/willmcgugan",
    )
    sponsor_message.add_row("Textualize", "[u blue link=https://www.textualize.io]https://www.textualize.io")

    message = Table.grid(padding=1)
    message.add_column()
    message.add_column(no_wrap=True)
    message.add_row(sponsor_message)

    message_panel = Panel(
        Align.center(
            Align.center(sponsor_message),
            vertical="middle",
        ),
        box=box.ROUNDED,
        padding=(1, 2),
        title="[b red]Thanks for trying out Rich!",
        border_style="bright_blue",
    )
    return message_panel, sponsor_message


class Vulns(str, Enum):
    xss = "xss"
    sql_injection = "sqli"
    ip_expose = "ip_expose"


def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=7, minimum_size=7),
    )
    layout["main"].split_row(
        Layout(name="side"),
        Layout(name="body", ratio=2, minimum_size=60),
    )
    layout["side"].split(Layout(name="box1", minimum_size=7), Layout(name="box2", minimum_size=15, ratio=2))
    return layout


def make_header() -> Panel:
    """Display Header."""
    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right")
    grid.add_row(
        "[b]Scan vuln[/b]",
        datetime.now().ctime().replace(":", "[blink]:[/]"),
    )
    return Panel(grid, style="white on blue")


def make_progress(total_files: int) -> [Progress, Progress, Table, Task, Task]:
    """Make the progress table."""
    job_progress = Progress(
        "{task.description}",
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    )

    task_scan_machine_learning = job_progress.add_task("[green]Machine Learning", total=total_files)
    task_scan_regex = job_progress.add_task("[magenta]Regex", total=total_files)

    total = sum(task.total for task in job_progress.tasks)

    overall_progress = Progress()
    overall_task = overall_progress.add_task("All Jobs", total=int(total))

    progress_table = Table.grid(expand=True, pad_edge=True)
    progress_table.add_row(
        Panel(Align.left(overall_progress, vertical="middle"), title="Overall Progress", border_style="green", padding=(1, 2), height=6),
        Panel(Align.left(job_progress, vertical="middle"), title="[b]Jobs", border_style="red", height=6, padding=(1, 2)),
    )

    return overall_progress, job_progress, progress_table, task_scan_machine_learning, task_scan_regex, overall_task


def make_panel_vulnerabilities_found(tree: Tree, key: str = "CTRL + V") -> Panel:
    """
    Make table vulnerabilities found

    return: Table
    """
    global vulns_global

    for idx, vulns in enumerate(vulns_global):
        branch = tree.add(f"[u cyan]🐘 [link file://{vulns[0][3]}]{vulns[0][3]}")

        for code, line, match, path in vulns:
            branch.add(f"[b magenta]{code}[/b magenta] - [b green]{line + 1}")

    return Panel(
        Align.left(tree),
        title=f"[b red]REGEX - {len(vulns_global)} Vulnerabilities found [/b red] Press [b blue] {key} [/b blue] to return to the main screen",
        border_style="red",
        padding=(1, 2),
    )


def make_prediction_message(pred_safety, pred_type) -> Panel:
    """Some example content."""
    prediction_message = Table.grid(padding=1)
    prediction_message.add_column(style="green", justify="right")
    prediction_message.add_column(no_wrap=True)
    prediction_message.add_row(
        "Safety:",
        f"[u blue]{pred_safety}",
    )
    prediction_message.add_row(
        "Vulnerability:",
        f"[u blue]{pred_type}",
    )

    message = Table.grid(padding=1)
    message.add_column()
    message.add_column(no_wrap=True)
    message.add_row(prediction_message)

    message_panel = Panel(
        Align.center(
            Align.center(prediction_message),
            vertical="middle",
        ),
        box=box.ROUNDED,
        padding=(1, 2),
        title="[b blue] Machine Learning",
        border_style="bright_blue",
    )
    return message_panel


def make_scan_regex_log() -> [Panel, Table]:
    """
    Make scan regex log

    return: [Painel, Table]
    """
    scan_regex_log = Table.grid(padding=1)
    scan_regex_log.add_column(style="green", justify="right")
    scan_regex_log.add_column(no_wrap=False)

    message_panel = Panel(
        scan_regex_log,
        box=box.ROUNDED,
        padding=(1, 2),
        title="[b red] Scanning Regex",
        border_style="red",
    )
    return message_panel, scan_regex_log


@app.command(help="Show the version of the CLI")
def version():
    """
    Show the version of the CLI
    """
    print(__version__)


@app.command(help="Create a new concept", epilog="Developed by: @giovannifranco1")
def new_concept():
    """
    Create a new concept.
    """
    print(BANNER)
    print("\n")

    _list_ontologies_painel()

    print("\n")
    ontology = Prompt.ask("Enter the ontology number to be add", default=None)
    print("\n")

    if ontology is None:
        print("[red]Ontology not found.[/red]")
        raise typer.Exit(code=1)

    if not ontology.isdigit():
        print("[red]Ontology not found.[/red]")
        raise typer.Exit(code=1)

    ontology = int(ontology)

    if ontology > len(utils.get_ontologies()):
        print("[red]Ontology not found.[/red]")
        raise typer.Exit(code=1)

    ontology = utils.get_ontologies()[ontology - 1]

    description = Prompt.ask("[blue]Enter the description of the concept[/blue]")
    format_regex = Prompt.ask("[blue]Enter the regex of the concept[/blue]")

    if utils.validate_regex(format_regex) is False:
        print(f"Invalid regex: [red]{format_regex}[/red]")
        raise typer.Exit(code=1)

    utils.print_painel("[yellow]Creating new concept ...[/yellow]")
    concepts = utils.create_concept(ontology, format_regex, description)

    print("[green]Concept created successfully.[/green]")
    print("")

    string_line_concepts_mounted = ""

    for concept in concepts:
        string_line_concepts_mounted += f"\nDescription: {concept['description']}\nFormat: [green]{concept['format']}[/green]\n"

    print(Panel(string_line_concepts_mounted, title=f"Concepts - {ontology}", border_style="green"))


@app.command(help="List all models")
def list_model():
    print(BANNER)
    print("")
    print("[yellow]Listing models ...[/yellow]")
    print("")

    _list_models_painel()


@app.command(help="Create a new model using a CSV file")
def new_model(path: Path):
    """
    Create a new model using a CSV file
    """

    print(BANNER)
    print("")

    if not path.exists():
        print(f"[red]The file or directory does not exist.[/red]")
        raise typer.Exit(code=1)

    if path.is_dir():
        print(f"[red]The path must be a file.[/red]")
        raise typer.Exit(code=1)

    if path.is_file() and path.suffix.lower() == ".csv":
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            SpinnerColumn(),
            transient=True,
        ) as progress:
            task_read_csv = progress.add_task("[green]Reading CSV ...[/green]", total=100)
            task_validate = progress.add_task("[green]validating ... [/green]", total=100)
            task_train_model = progress.add_task("[green]Compiling model ...[/green]", total=100)
            task_save_model = progress.add_task("[green]Saving model ...[/green]", total=100)

            ds = pd.read_csv(path)
            models_length = len(model_utils.get_models())

            progress.update(task_read_csv, completed=100, description=f"[green]Reading CSV ✔[/green]")

            expected_columns = ["code", "safety", "type"]
            csv_columns = list(ds.columns)

            if csv_columns != expected_columns:
                print(f"[red]The columns must be {expected_columns}.[/red]")
                raise typer.Exit(code=1)

            if models_length > model_utils.max_length:
                print(f"[red]The maximum number of models has been reached.[/red]")
                raise typer.Exit(code=1)

            progress.update(task_validate, completed=100, description=f"[green]Validating ✔[/green]")

            model, accuracy_safety, accuracy_type, report_safety, report_type = model_utils.train_create_model(ds)
            progress.update(task_train_model, completed=100, description=f"[green]Compiling model ✔[/green]")

            joblib.dump(model, f"{model_utils.models_path}/model_{models_length + 1}.joblib")
            progress.update(task_save_model, completed=100, description=f"[green]Saving model ✔[/green]")

            print("")
            print(f"[green]Model compiled successfully.[/green]")
            print("")

            print(f"Accuracy Security: {accuracy_safety}")
            print("Security Classification Report:\n", report_safety)

            print(f"Type Accuracy: {accuracy_type}")
            print("Type Classification Report:\n", report_type)

            _list_models_painel()


@app.command(help="Remove a model")
def remove_model():
    _list_models_painel()

    print("")
    model = Prompt.ask("Enter the model number to be removed", default=None)

    if model is None:
        print("[red]Model not found.[/red]")
        raise typer.Exit(code=1)

    if not model.isdigit():
        print("[red]Model not found.[/red]")
        raise typer.Exit(code=1)

    model = int(model)

    if model > len(model_utils.get_models()):
        print("[red]Model not found.[/red]")
        raise typer.Exit(code=1)

    model_utils.remove_model(model)

    print("")
    print("[green]Model removed successfully.[/green]")


@app.command(help="Find vulnerabilities in PHP files using Machine Learning")
def scan_machine_learning(path: Path):
    """
    Find vulnerabilities in PHP files using Machine Learning
    """
    print(BANNER)
    print("")

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        SpinnerColumn(),
        transient=True,
    ) as progress:
        task_scan = progress.add_task("[green]Scanning ...[/green]", total=100)

        predictions = model_utils.scan(path)
        pred_safety, pred_type = model_utils.mode_predictions(predictions)

        progress.update(task_scan, completed=100, description=f"[green]Scanning ✔[/green]")

    print("")
    string_output_mounted = f"[yellow]Security:[/yellow] {pred_safety}\n[yellow]Vulnerability:[/yellow] {pred_type}"
    print(Panel(string_output_mounted, title="Machine Learning", border_style="blue"))


@app.command(help="Find vulnerabilities in PHP files using REGEX e Machine Learning")
def scan_php(path: Path, vulnerability: Annotated[Vulns, typer.Option(case_sensitive=False)]):
    """
    Find vulnerabilities in PHP files using REGEX e Machine Learning
    """
    print(BANNER)

    global vulns_global
    global log_scan_full

    if not path.exists():
        print(f"[red]The file or directory does not exist.[/red]")
        raise typer.Exit(code=1)

    pred_safety = None
    pred_type = None

    vuln_classes = utils.get_vulnerability_classes()
    vulns_list = [(_class.name, _class.keyname) for _class in vuln_classes]
    Vulnerability = [_class for _class in vuln_classes if _class.keyname == vulnerability][0]
    is_save_log = Confirm.ask("Do you want to save?")
    tree_vulnerabilities = Tree(f"[bold cyan]:open_file_folder: [link file://{path}]{path}", guide_style="bold bright_blue")

    if is_save_log:
        path_log = Prompt.ask("Enter the path to save the log", default="log.txt")
        path_log = Path(path_log)

    if path.is_dir():
        print(f"[yellow]Checking files in the directory {path} ...[/yellow]")
        print("")

        files = path.glob("**/*.php")
        files = list(files)
        
        if len(list(files)) == 0:
            print("[red]No files found.[/red]")
            raise typer.Exit(code=1)

        overall_progress, job_progress, progress_table, task_scan_machine_learning, task_scan_regex, overall_task = make_progress(
            len(list(files))
        )

        message_panel, table_scan_log = make_scan_regex_log()

        spinner_progress_box1 = Progress(
            SpinnerColumn(),
        )
        spinner_progress_box1.add_task("Task 1", total=100)

        try:
            directory = os.path.abspath(sys.argv[1])
        except IndexError:
            print("[b]Usage:[/] python tree.py <DIRECTORY>")
        else:
            tree_path = Tree(
                f":open_file_folder: [u blue link file://{directory}]{directory}",
                guide_style="bold bright_blue",
            )
            walk_directory(path, tree_path)

        layout["header"].update(make_header())
        layout["box1"].update(Panel(spinner_progress_box1, title="[b blue]Machine Learning", border_style="blue"))
        layout["box2"].update(
            Panel(
                tree_path,
                box=box.ROUNDED,
                padding=(1, 2),
                title="[b blue] Tree [/b blue] Press [b red] CTRL + A [/b red] to return to the main screen",
                border_style="bright_blue",
            )
        )
        layout["body"].update(message_panel)
        layout["footer"].update(progress_table)

        with Live(layout, refresh_per_second=10, screen=True, vertical_overflow="visible") as live:
            with ThreadPoolExecutor() as executor:
                executor.submit(
                    _scan_regex, path, Vulnerability, job_progress, task_scan_regex, overall_progress, overall_task, table_scan_log, live
                )
                executor.submit(_scan_machine_lerning, path, job_progress, task_scan_machine_learning, overall_progress, overall_task)

        pred_safety, pred_type = model_utils.mode_predictions(predictions_global)
        layout["body"].update(make_panel_vulnerabilities_found(tree_vulnerabilities))

    if path.is_file() and path.suffix.lower() == ".php":
        console = Console()
        vulns = scanning_utils.scan(path, Vulnerability)
        predictions = scanning_utils.scan_machine_lerning(path)[0]

        if vulns:
            vulns_global.append(vulns)

        pred_safety = predictions[0]
        pred_type = predictions[1]

        with open(path, "r") as code_php:
            syntax = Syntax(code_php.read(), "PHP", line_numbers=True, theme="one-dark")

        layout["body"].update(
            Panel(
                syntax,
                title=f"[b blue] Code - {path} [/b blue] Press [b red] CTRL + E [/b red] to return to the main screen",
                border_style="green",
            )
        )
        layout["box2"].update(make_panel_vulnerabilities_found(tree_vulnerabilities))
        layout["header"].update(make_header())

    total = len(vulns_global)
    is_vuln = total > 0
    string_lines_vulnerabilities_mounted = ""

    string_lines_lins_mounted = ""

    if is_save_log:
        print(f"[yellow]Saving log in {path_log} ...[/yellow]")

        string_lines_log_mounted = f"Vulnerabilities found in {path}:\n\n"

        for vulns in vulns_global:
            for vuln in vulns:
                if isinstance(vuln, list):
                    vuln = vuln[0]

                code, line, match, path = vuln
                string_lines_log_mounted += f"{code} - Line: {line} | {path}\n"

        if path_log.is_dir():
            path = path_log / "log.txt"
            path_log = path

        with open(path_log, "w") as log_file:
            if not is_vuln:
                log_file.write("No vulnerabilities found.\n")
            else:
                log_file.write(string_lines_log_mounted)

    layout["box1"].update(make_prediction_message(pred_safety, pred_type))

    console = Console()
    console.screen = True
    console.print(layout)
    print("[b cyan]Press [b red] COMMAND [/b red][/b cyan]")

    while True:
        k = readkey()

        match k:
            case key.CTRL_A:
                with console.pager(styles=True):
                    console.screen = True
                    console.print(
                        Panel(
                            tree_path,
                            box=box.ROUNDED,
                            padding=(1, 2),
                            title="[b blue] Tree [/b blue] Press [b red] Q [/b red] to return to the main screen",
                            border_style="bright_blue",
                        )
                    )
            case key.CTRL_V:
                with console.pager(styles=True):
                    console.screen = True
                    console.print(
                        Panel(
                            Align.left(tree_vulnerabilities),
                            title=f"[b red]REGEX - {len(vulns_global)} Vulnerabilities found [/b red] Press [b blue] Q [/b blue] to return to the main screen",
                            border_style="red",
                            padding=(1, 2),
                        )
                    )
            case key.CTRL_F:
                with console.pager(styles=True):
                    console.screen = True
                    console.print(log_scan_full)
            case key.CTRL_E:
                with console.pager(styles=True):
                    console.screen = True
                    console.print(
                        Panel(
                            syntax,
                            title=f"[b blue] Code - {path}  [/b blue] Press [b red] Q [/b red] to return to the main screen",
                            border_style="green",
                        )
                    )


def walk_directory(path: Path, tree: Tree) -> None:
    """Recursively build a Tree with directory contents."""

    paths = sorted(
        path.iterdir(),
        key=lambda path: (path.is_file(), path.name.lower()),
    )

    length = len(paths)

    is_exceeded = False

    if len(paths) > 3:
        paths = paths[:3]
        is_exceeded = True

    for idx, path in enumerate(paths):
        if path.name.startswith("."):
            continue

        if path.is_dir():
            style = "dim" if path.name.startswith("__") else ""
            branch = tree.add(
                f"[bold magenta]:open_file_folder: [link file://{path}]{escape(path.name)}",
                style=style,
                guide_style=style,
            )
            walk_directory(path, branch)
        else:
            text_filename = Text(path.name, "cyan")
            text_filename.highlight_regex(r"\..*$", "bold red")
            text_filename.stylize(f"link file://{path}")
            file_size = path.stat().st_size
            text_filename.append(f" ({decimal(file_size)})", "blue")
            icon = "🐘 " if path.suffix == ".php" else "📄 "
            tree.add(Text(icon) + text_filename)
            if is_exceeded and idx is len(paths) - 1:
                tree.add(Text(f"... ({length})", "gray"))


def _list_models_painel():
    """
    List all models

    return: None
    """
    string_lines_models_mounted = ""

    models = model_utils.get_models()
    for idx, model in enumerate(models):
        string_lines_models_mounted += f"{idx + 1} - [yellow]Model [/yellow][green]{model}[/green]\n"

    print(Panel(string_lines_models_mounted, title="Models", border_style="green"))


def _list_ontologies_painel():
    """
    List all ontologies

    return: None
    """
    string_lines_ontologies_mounted = ""

    ontologies = utils.get_ontologies()
    for idx, ontology in enumerate(ontologies):
        string_lines_ontologies_mounted += f"{idx + 1} - [yellow]Ontology [/yellow][green]{ontology}[/green]\n"

    print(Panel(string_lines_ontologies_mounted, title="Ontologies", border_style="green"))


def _scan_regex(
    path: Path,
    Vulnerability: Vulnerability,
    job_progress: Progress,
    task: Task,
    overall_progress: Progress,
    overall_task: Task,
    table_scan_log: Table,
    live: Live,
):
    """
    Scan regex

    return: None
    """
    global vulns_global
    global log_scan_full

    files = path.glob("**/*.php")
    rows_vuln = []
    rows = []

    for _path in files:
        text_checking = f"[yellow]Checking file [u yellow]{_path}[/u yellow] ...[/yellow]"
        table_scan_log.add_row(Align.left(text_checking), "Loading ...")
        vulns = scanning_utils.scan(_path, Vulnerability)
        rows.append((text_checking, "Loading ..."))

        if vulns:
            rows_vuln.append(table_scan_log.row_count)
            vulns_global.append(vulns)
            rows[table_scan_log.row_count - 1] = (Align.left(text_checking), "[red]Vulnerabilities found[/red]")
            log_scan_full.add_row(Align.left(text_checking), "[red]Vulnerabilities found[/red]")
        else:
            rows[table_scan_log.row_count - 1] = (Align.left(text_checking), "[green]OK ✔[/green]")
            log_scan_full.add_row(Align.left(text_checking), "[green]OK ✔[/green]")

        table_scan_log = Table.grid(padding=1)
        table_scan_log.add_column(style="green", justify="right")
        table_scan_log.add_column(no_wrap=False)

        length = len(rows)

        if length > 25:
            rows = rows[length - 20 :]

        for row in rows:
            if isinstance(row, tuple):
                table_scan_log.add_row(*row)

        layout["body"].update(
            Panel(table_scan_log, title=f"REGEX - {len(vulns_global)} Vulnerabilities found", border_style="red", padding=(1, 2))
        )

        job_progress.advance(task)
        completed = sum(task.completed for task in job_progress.tasks)
        overall_progress.update(overall_task, completed=completed)


def _scan_machine_lerning(path: Path, job_progress: Progress, task: Task, overall_progress: Progress, overall_task: Task):
    """
    Scan machine learning

    return: None
    """
    predictions = scanning_utils.scan_machine_lerning(path, job_progress, task)
    predictions_global.append(predictions)

    completed = sum(task.completed for task in job_progress.tasks)
    overall_progress.update(overall_task, completed=completed)


layout = make_layout()

if __name__ == "__main__":
    app()
