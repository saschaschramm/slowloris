import csv
from csv import DictReader
from typing import Dict, List


def read(path: str) -> List[Dict[str, str]]:
    flows: List[Dict[str, str]] = []
    with open(path, mode="r") as file:
        reader: DictReader = DictReader(file, skipinitialspace=True)
        for line in reader:
            flows.append(line)
        flows = sorted(flows, key=lambda x: x["Timestamp"], reverse=True)
        return flows
