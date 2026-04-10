from abc import ABC, abstractmethod
from typing import Mapping

from dw_auth.domain import Principal


class Authenticator(ABC):
    @abstractmethod
    def authenticate(self, headers: Mapping[str, str] | None) -> Principal:
        raise NotImplementedError()
