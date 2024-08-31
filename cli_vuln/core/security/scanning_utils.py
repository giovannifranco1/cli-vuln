from pathlib import Path
from typing import List, Tuple
from cli_vuln.core.security import model_utils
from cli_vuln.common.abc import Vulnerability
from rich.progress import Progress, Task


def scan(path: Path, Vulnerability: Vulnerability) -> List:
    vuln_obj = Vulnerability(path)
    vulns = vuln_obj.find()

    if vulns:
        for idx, vuln in enumerate(vulns):
            vulns[idx] = vuln + (path,)

    return vulns


def scan_machine_lerning(path: Path, job_progress: Progress = None, task: Task = None) -> List[Tuple[str, str]]:
    """
    This function is used to scan the machine learning models

    return: List[Tuple[str, str]]
    """
    output = []

    if path.is_dir():
        for _path in path.glob("**/*.php"):
            if _path.is_dir():
                continue

            with open(_path, "r", encoding="iso-8859-1") as file_php:
                predictions = model_utils.compile_models(file_php.read())
                output.append(predictions)

                if not job_progress is None:
                    job_progress.advance(task)

    if path.is_file() and path.suffix.lower() == ".php":
        with open(path, "r", encoding="iso-8859-1") as file_php:
            model_utils.compile_models(file_php.read())

        predictions = model_utils.compile_models(path)
        output.append(predictions)

    return output
