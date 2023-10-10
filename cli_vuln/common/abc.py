import re
import json

from typing import List, Tuple
from abc import ABC, abstractmethod


class Vulnerability(ABC):
    """(common) Vulnerability abstract base class.

    Abstract base class for common PHP vulnerabilities.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

        if not issubclass(self.__class__, Vulnerability):
            raise NotImplementedError("you cannot initialise this class")

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of common vulnerability.

        Returns:
            str: name of common vulnerability
        """
        pass

    @property
    @abstractmethod
    def keyname(self) -> str:
        """Keyname of common vulnerability used in `--vulns` command line argument.

        Returns:
            str: keyname of common vulnerability
        """
        pass

    @property
    @abstractmethod
    def ontology_json(self) -> str:
        """Ontology JSON file path.

        Returns:
            str: ontology JSON file path
        """
        pass

    @abstractmethod
    def find(self) -> List[Tuple[str, int, re.Match]]:
        """Find all vulnerable lines of code.

        Abstract method to find all vulnerable lines of code,
        and return the lines, line numbers and regex matches found.

        Returns:
            List[Tuple[str, int, re.Match]]: list of potential vulnerable code containing the line, line number and regex match
        """
        pass

    def get_lines(self) -> List[str]:
        """Get all lines of file.

        Get all stripped lines of the specified file in
        Vulnerability subclass.

        Returns:
            List[str]: list of lines from file
        """
        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f.readlines()]
        return lines

    def __remove_indent(self, line: str) -> str:
        while line[0] == " " or line[0] == "\t":
            line = line[1:]
        return line

    def _find(self, regex: str, ignore_case: bool = True) -> List[Tuple[str, int, object]]:
        vulns = []

        for i, line in enumerate(self.get_lines()):
            match = re.search(f"({regex})", line, re.IGNORECASE if ignore_case else 0)

            if match:
                vulns.append((self.__remove_indent(line), i, match.group(1)))

        return vulns

    def get_links(self) -> List[str]:
        links = []

        with open(self.ontology_json, "r") as ontology_json:
            data = json.load(ontology_json)

        links = data["ontology"]["links"]

        return links
