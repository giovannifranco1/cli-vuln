import re
import json
from cli_vuln.common.abc import Vulnerability


class Xss(Vulnerability):
    name = "CROSS-SITE SCRIPTING (XSS)"
    keyname = "xss"
    ontology_json = "cli_vuln/out/xss.json"

    def __init__(self, file_path):
        super().__init__(file_path)

    def find(self):
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
