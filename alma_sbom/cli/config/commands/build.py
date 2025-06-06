import argparse
from dataclasses import dataclass

from alma_sbom.cli.config import CommonConfig

@dataclass
class BuildConfig(CommonConfig):
    build_id: str = None

    def __post_init__(self) -> None:
        self._validate()
        super().__post_init__()

    def _validate(self) -> None:
        if not self.build_id:
            raise ValueError(
                'Unexpected situation has occurred'
                'build_id must not be empty'
            )

    @classmethod
    def from_base(cls, base: CommonConfig, build_id: str) -> 'BuildConfig':
        base_fields = vars(base)
        return cls(**base_fields, build_id=build_id)

    @classmethod
    def from_base_args(cls, base: CommonConfig, args: argparse.Namespace) -> 'BuildConfig':
        return cls.from_base(base, build_id=args.build_id)

    @staticmethod
    def add_arguments(parser: argparse._SubParsersAction) -> None:
        build_parser = parser.add_parser('build', help='Generate build SBOM')
        build_parser.add_argument(
            '--build-id',
            type=str,
            help='SHA256 hash of an RPM package',
            required=True,
        )

