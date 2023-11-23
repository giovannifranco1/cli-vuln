import re
import json

from typing import List, Tuple
from abc import ABC, abstractmethod


class Vulnerability(ABC):
    def __init__(self, file_path: str):
        self.file_path = file_path

        if not issubclass(self.__class__, Vulnerability):
            raise NotImplementedError("you cannot initialise this class")

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def keyname(self) -> str:
        pass

    @property
    @abstractmethod
    def ontology_json(self) -> str:
        pass

    def find(self) -> List[Tuple[str, int, re.Match]]:
        with open(self.ontology_json, "r") as ontology_json:
            xss_data = json.load(ontology_json)

        expressions = map(lambda x: x["format"], xss_data["ontology"]["concepts"])
        output = []

        try:
            for regex in expressions:
                re.compile(regex)
                output += self._find(regex, False)

                if len(output) > 0:
                    break

        except re.error:
            print("Invalid regex")
            exit()

        return output
        pass

    def get_lines(self) -> List[str]:
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
