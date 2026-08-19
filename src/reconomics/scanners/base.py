from abc import ABC, abstractmethod

from reconomics.models import ScanResult
from reconomics.targets import TargetType


class Scanner(ABC):
    supported_target_types: set[TargetType] = set()

    def supports(self, target_type: TargetType) -> bool:
        return target_type in self.supported_target_types

    @abstractmethod
    def scan(self, target: str) -> ScanResult:
        raise NotImplementedError