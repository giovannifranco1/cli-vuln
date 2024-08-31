import re
import json
from cli_vuln.common.abc import Vulnerability


class IPExpose(Vulnerability):
    name = "IP EXPOSE"
    keyname = "ip_expose"
    ontology_json = "cli_vuln/out/ip_expose.json"

    def __init__(self, file_path):
        super().__init__(file_path)
