import re
import json
from cli_vuln.common.abc import Vulnerability


class Xss(Vulnerability):
    name = "CROSS-SITE SCRIPTING (XSS)"
    keyname = "xss"
    ontology_json = "cli_vuln/out/xss.json"

    def __init__(self, file_path):
        super().__init__(file_path)
