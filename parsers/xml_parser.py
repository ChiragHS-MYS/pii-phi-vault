"""
XML parser, backed by xml.etree.ElementTree. Yields a Field for every
element's text content and every attribute value, with setters that
write straight back into the live ElementTree element.
"""
import xml.etree.ElementTree as ET
from typing import List
from parsers.base_parser import BaseParser
from core.schema import Field


class XMLParser(BaseParser):
    def load(self, raw_text: str) -> ET.Element:
        return ET.fromstring(raw_text)

    def dump(self, doc: ET.Element) -> str:
        return ET.tostring(doc, encoding="unicode")

    def extract_fields(self, doc: ET.Element) -> List[Field]:
        fields: List[Field] = []
        self._walk(doc, path=doc.tag, fields=fields)
        return fields

    def _walk(self, elem: ET.Element, path: str, fields: List[Field]):
        # element text
        if elem.text and elem.text.strip():
            fields.append(self._text_field(elem, path))

        # attributes
        for attr_name, attr_val in elem.attrib.items():
            attr_path = f"{path}[@{attr_name}]"
            fields.append(self._attr_field(elem, attr_name, attr_val, attr_path))

        # children
        for child in elem:
            child_path = f"{path}/{child.tag}"
            self._walk(child, child_path, fields)

    @staticmethod
    def _text_field(elem: ET.Element, path: str) -> Field:
        def setter(new_value: str, elem=elem):
            elem.text = new_value
        return Field(path=path, value=elem.text, set_value=setter)

    @staticmethod
    def _attr_field(elem: ET.Element, attr_name: str, value: str, path: str) -> Field:
        def setter(new_value: str, elem=elem, attr_name=attr_name):
            elem.set(attr_name, new_value)
        return Field(path=path, value=value, set_value=setter)
