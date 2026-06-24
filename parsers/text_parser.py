import re
from typing import List
from parsers.base_parser import BaseParser
from core.schema import Field


class PlainTextParser(BaseParser):
    def load(self, raw_text: str) -> dict:
        # Split by newlines but keep the separator/newlines intact
        lines = raw_text.splitlines(keepends=True)
        return {"lines": lines}

    def extract_fields(self, doc: dict) -> List[Field]:
        fields = []
        # Key must be alphanumeric / space / hyphen / underscore, length 2 to 40.
        kv_pattern = re.compile(r"^([a-zA-Z0-9_\-\s\(\)/]{2,40})\s*:\s*(.+)$")

        for i, line in enumerate(doc["lines"]):
            # Strip trailing newline for matching
            line_content = line.rstrip("\r\n")
            newline_suffix = line[len(line_content):]

            m = kv_pattern.match(line_content)
            if m:
                key, val = m.groups()
                # Determine the prefix (key + separators) before the value
                prefix_len = m.start(2)
                prefix = line_content[:prefix_len]

                # Create a closure capturing the current index and formatting
                def make_setter(idx=i, pref=prefix, suffix=newline_suffix):
                    def setter(new_val: str):
                        doc["lines"][idx] = pref + new_val + suffix
                    return setter

                fields.append(Field(path=key.strip(), value=val, set_value=make_setter()))
            else:
                # Treated as standard free text
                def make_setter(idx=i, suffix=newline_suffix):
                    def setter(new_val: str):
                        doc["lines"][idx] = new_val + suffix
                    return setter

                fields.append(Field(path="text", value=line_content, set_value=make_setter()))

        return fields

    def dump(self, doc: dict) -> str:
        return "".join(doc["lines"])

