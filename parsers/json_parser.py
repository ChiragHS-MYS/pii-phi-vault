"""
JSON parser. Recursively walks the dict/list structure, yields a Field
for every string leaf, with a closure that can mutate that exact leaf
back in the original structure (dicts/lists are mutable by reference).
"""
import json
from typing import List, Any
from parsers.base_parser import BaseParser
from core.schema import Field


class JSONParser(BaseParser):
    def load(self, raw_text: str) -> Any:
        return json.loads(raw_text)

    def dump(self, doc) -> str:
        return json.dumps(doc, indent=2, ensure_ascii=False)

    def extract_fields(self, doc) -> List[Field]:
        fields: List[Field] = []
        self._walk(doc, path="$", fields=fields)
        return fields

    def _walk(self, node, path: str, fields: List[Field]):
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = f"{path}.{key}"
                if isinstance(value, str):
                    fields.append(self._make_field(node, key, value, child_path))
                elif isinstance(value, (dict, list)):
                    self._walk(value, child_path, fields)
                # numbers/bools/None are left alone

        elif isinstance(node, list):
            for idx, value in enumerate(node):
                child_path = f"{path}[{idx}]"
                if isinstance(value, str):
                    fields.append(self._make_field(node, idx, value, child_path))
                elif isinstance(value, (dict, list)):
                    self._walk(value, child_path, fields)

    @staticmethod
    def _make_field(container, key, value, path) -> Field:
        def setter(new_value: str, container=container, key=key):
            container[key] = new_value
        return Field(path=path, value=value, set_value=setter)
