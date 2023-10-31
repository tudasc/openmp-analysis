from dataclasses import dataclass
from datetime import datetime

@dataclass
class GithubMetadata:
    name: str = None
    language: str = None
    cloneUrl: str = None
    stars: int = 0
    pushDate: datetime = None
