
from alma_sbom.type import SbomRecordType
from .document import Document
from .spdx.document import SPDXDocument
from .spdx3.document import SPDX3Document
from .cyclonedx.document import CDXDocument

document_classes: dict[SbomRecordType, type[Document]] = {
    SbomRecordType.SPDX: SPDXDocument,
    SbomRecordType.SPDX3: SPDX3Document,
    SbomRecordType.CYCLONEDX: CDXDocument,
}

def document_factory(format: SbomRecordType) -> type[Document]:
    return document_classes.get(format)

