import json
import os
import uuid
from datetime import datetime
from semantic_version import Version
from typing import Callable

from spdx_tools.spdx3.model.spdx_document import SpdxDocument
from spdx_tools.spdx3.model import CreationInfo
from spdx_tools.spdx3.model.software import Package as PackageModel
from spdx_tools.spdx3.model.build import Build as BuildModel
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.writer.json_ld.json_ld_converter import convert_payload_to_json_ld_list_of_elements
from spdx_tools.spdx3.writer.json_ld import json_ld_writer
# from spdx_tools.spdx3.writer.json_ld.json_ld_writer import write_payload

from alma_sbom.type import SbomFileFormatType
from alma_sbom.data.models import Package, Build
from alma_sbom.formats.document import Document as AlmasbomDocument

from . import constants as spdx3_consts
from .element import element_from_package


def write_payload_jsonld(payload: Payload) -> str:
    element_list = convert_payload_to_json_ld_list_of_elements(payload)
    with open(os.path.join(os.path.dirname(json_ld_writer.__file__), "context.json"), "r") as infile:
        context = json.load(infile)
    complete_dict = {"@context": context, "@graph": element_list}
    return complete_dict

class SPDX3Formatter:
    FORMATTERS = {
        SbomFileFormatType.JSON: write_payload_jsonld,
    }
    formatter: Callable[[Payload], str]

    def __init__(self, file_format: SbomFileFormatType) -> None:
        self.formatter = self.FORMATTERS[file_format]

class SPDX3Document(AlmasbomDocument):
    document: SpdxDocument
    payload: Payload
    formatter: SPDX3Formatter
    doc_name: str
    doc_uuid: str
    _next_id: int = 0

    def __init__(self, file_format_type: SbomFileFormatType, doc_name: str) -> None:
        self.doc_name = doc_name
        self.uuid = uuid.uuid4()

        creation_info = CreationInfo(
            spec_version=Version('3.0.1'),
            created=datetime.now(),
            created_by=[f"Organization: {spdx3_consts.ALMAOS_VENDOR}"],
            profile=[],
            data_license=spdx3_consts.ALMAOS_SBOMLICENSE,
            # created_using: List[str] = None, # SPDXID of Tools
        )
        self.document = SpdxDocument(
            spdx_id="SPDXRef-DOCUMENT",
            name=doc_name,
            element=[],
            root_element=[],
            creation_info=creation_info,
        )
        self.formatter = SPDX3Formatter(file_format_type)

        spdx_id_map = {self.document.spdx_id: self.document}
        self.payload = Payload(spdx_id_map)

        # tool = Tool()

        self._next_id = 0

    @classmethod
    def from_package(cls, package: Package, file_format_type: SbomFileFormatType) -> 'SPDX3Document':
        doc_name = package.get_doc_name()
        doc = cls(file_format_type, doc_name)

        package_model = element_from_package(package, doc._get_next_package_id())

        doc.payload.add_element(package_model)
        doc.document.element = [package_model.spdx_id]
        doc.document.root_element = [package_model.spdx_id]

        return doc

    @classmethod
    def from_build(cls, package: Build, file_format_type: SbomFileFormatType) -> 'SPDX3Document':
        raise NotImplementedError()

    def write(self, output_file: str) -> None:
        output = self.formatter.formatter(self.payload)
        with open(output_file, "w") as fdobj:
            json.dump(output, fdobj, indent=4)

    def _get_next_package_id(self) -> str:
        """Return an identifier that can be assigned to a package in this document.

        Further reading:
        https://spdx.github.io/spdx-spec/v2-draft/package-information/#72-package-spdx-identifier-field
        """
        cur_id = self._next_id
        self._next_id += 1
        return f"SPDXRef-{cur_id}"

