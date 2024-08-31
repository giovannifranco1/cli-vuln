import os
import sys
import re
import inspect
import importlib
import json

from rich import print

from cli_vuln.common.abc import Vulnerability

vulnerability_classes_path = os.path.join("cli_vuln", "vulnerabilities")
ontologies_path = os.path.join("cli_vuln", "out")


def sys_to_mod_path(*args):
    """Convert system file path to Python module path

    Converts a system file path to
    Python module path for dynamic importing.

    Returns:
        str: Python module path
    """
    return os.path.join(*[x[:-3] if x.endswith(".py") else x for x in args]).replace(os.path.sep, ".")


def get_vulnerability_classes():
    """Returns common vulnerability classes

    Returns:
        list: list of common vulnerability classes
    """
    items = os.listdir(vulnerability_classes_path)
    items.remove("__init__.py")

    classes = []

    for item in items:
        if not item.endswith(".py"):
            continue

        module_name = sys_to_mod_path(vulnerability_classes_path, item)

        if not importlib.import_module(module_name):
            continue

        for _, Class in inspect.getmembers(sys.modules[module_name], inspect.isclass):
            if issubclass(Class, Vulnerability) and Class != Vulnerability:
                classes.append(Class)

    return classes


def get_ontologies() -> list:
    """Returns ontologies

    Returns:
        list: list of ontologies
    """
    ontologies = []

    [ontologies.append(ontology) for ontology in os.listdir(ontologies_path)]

    return ontologies


def create_concept(ontology_path: str, format_regex: str, description: str):
    """Create ontology

    Args:
        ontology_path (str): ontology path
        format (str): format
        description (str): description
    """
    ontology_path = os.path.join(ontologies_path, ontology_path)

    with open(ontology_path, "r") as ontology_json:
        data = json.load(ontology_json)
        concepts = data["ontology"]["concepts"]
        concepts.append(
            {
                "format": format_regex,
                "description": description,
                "level": len(concepts) + 1,
            }
        )

        data["ontology"]["concepts"] = concepts

        with open(ontology_path, "w") as ontology_json:
            ontology_json.write(json.dumps(data, indent=4))

    return concepts


def validate_regex(regex: str):
    """Validate regex

    Args:
        regex (str): regex
    """
    try:
        re.compile(regex)
        return True
    except re.error:
        return False


def print_painel(string: str):
    """Prints painel

    Args:
        string (str): string to print
    """

    print("\n")
    print(string)
    print("\n")
