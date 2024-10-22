import re
import json
from cli_vuln.common.abc import Vulnerability


class SQLInjection(Vulnerability):
    name = "SQL INJECTION"
    keyname = "sqli"
    ontology_json = "cli_vuln/out/sql_injection.json"

    def __init__(self, file_path):
        super().__init__(file_path)
