from dataclasses import dataclass
from ..config import CommonConfig

@dataclass
class BuildConfig(CommonConfig):
    build_id: str = None

    def __post_init__(self):
        if not self.build_id:
            raise ValueError("build_id must not be empty")
        super().__post_init__()