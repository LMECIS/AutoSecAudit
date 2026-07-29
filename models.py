# models.py
from dataclasses import dataclass, field, asdict
from typing import Optional, Literal
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Унифицированная структура для всех находок."""
    issue: str
    severity: Severity
    module: str
    description: Optional[str] = None
    solution: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    header: Optional[str] = None
    cookie: Optional[str] = None
    technology: Optional[str] = None
    subdomain: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    file: Optional[str] = None
    record: Optional[str] = None
    method: Optional[str] = None
    origin: Optional[str] = None
    credentials: Optional[str] = None
    info: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Конвертирует в словарь для JSON, убирая None значения."""
        result = asdict(self)
        result["severity"] = self.severity.value
        return {k: v for k, v in result.items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Создаёт Finding из словаря."""
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = Severity(data["severity"])
        # Оставляем только известные поля
        known_fields = set(cls.__dataclass_fields__.keys())
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    def unique_key(self) -> str:
        """Уникальный идентификатор для сравнения в diff-режиме."""
        parts = [self.module, self.severity.value, self.issue]
        for attr in (self.url, self.path, self.header, self.port,
                     self.subdomain, self.cookie, self.technology):
            if attr is not None:
                parts.append(str(attr))
        return "|".join(parts)


@dataclass
class ModuleResult:
    """Результат работы одного модуля."""
    status: Literal["PASS", "FAIL", "ERROR"]
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": [f.to_dict() if isinstance(f, Finding) else f
                         for f in self.findings]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ModuleResult":
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(status=data.get("status", "UNKNOWN"), findings=findings)


@dataclass
class AuditReport:
    """Полный отчёт аудита."""
    target: str
    scan_date: str
    options: dict
    modules: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_date": self.scan_date,
            "options": self.options,
            "modules": {k: (v.to_dict() if hasattr(v, "to_dict") else v)
                        for k, v in self.modules.items()}
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditReport":
        modules = {
            k: ModuleResult.from_dict(v)
            for k, v in data.get("modules", {}).items()
        }
        return cls(
            target=data["target"],
            scan_date=data["scan_date"],
            options=data.get("options", {}),
            modules=modules
        )

    def all_findings(self) -> list:
        """Все находки из всех модулей."""
        findings = []
        for module_result in self.modules.values():
            if hasattr(module_result, "findings"):
                findings.extend(module_result.findings)
        return findings