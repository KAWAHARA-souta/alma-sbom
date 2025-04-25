
from spdx_tools.spdx3.model.spdx_document import SpdxDocument
from spdx_tools.spdx3.model import CreationInfo
from spdx_tools.spdx3.model.software import Package as PackageModel
from spdx_tools.spdx3.model.build import Build as BuildModel
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.writer.json_ld.json_ld_writer import write_payload

from alma_sbom.type import SbomFileFormatType
from alma_sbom.data.models import Package, Build
from alma_sbom.formats.document import Document as AlmasbomDocument


class SPDX3Formatter:

    def __init__(self, file_format: SbomFileFormatType) -> None:
        raise NotImplementedError()

class SPDX3Document(AlmasbomDocument):
    document: SpdxDocument
    formatter: SPDX3Formatter
    doc_name: str
    doc_uuid: str
    _next_id: int = 0

    def __init__(self, file_format_type: SbomFileFormatType, doc_name: str) -> None:
        raise NotImplementedError()

    @classmethod
    def from_package(cls, package: Package, file_format_type: SbomFileFormatType) -> 'SPDX3Document':
        raise NotImplementedError()

    @classmethod
    def from_build(cls, package: Build, file_format_type: SbomFileFormatType) -> 'SPDX3Document':
        raise NotImplementedError()

    def write(self, output_file: str) -> None:
        raise NotImplementedError()

