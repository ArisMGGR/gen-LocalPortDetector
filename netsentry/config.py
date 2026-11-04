"""Configuration file loading and validation."""
from __future__ import annotations

import configparser
import ipaddress
from dataclasses import dataclass, field, fields
from typing import List

DEFAULT_CONFIG_PATH = "/etc/netsentry/netsentry.conf"
SEVERITIES = ("info", "warning", "critical")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class ConfigError(Exception):
    pass


@dataclass
class GeneralConfig:
    log_level: str = "INFO"
    min_severity: str = "warning"    # lowest event severity that triggers a notification


@dataclass
class ScanConfig:
    interface: str = ""              # empty: the interface of the default route
    subnet: str = ""                 # empty: the interface's own subnet
    interval: int = 60               # seconds between scans
    timeout: float = 2.0             # seconds to wait for replies after the last request
    passes: int = 2                  # ARP requests sent to each address per scan
    max_hosts: int = 4096            # refuse to sweep subnets larger than this
    resolve_hostnames: bool = True


@dataclass
class DetectionConfig:
    offline_after: int = 600         # seconds without a reply before a device counts as offline
    baseline_on_first_run: bool = True
    alert_on_unknown_return: bool = True
    conflict_alerts: bool = True
    watch_gateway: bool = True


@dataclass
class StorageConfig:
    database: str = "/var/lib/netsentry/devices.db"
    event_log: str = "/var/log/netsentry/events.jsonl"
    daily_log_dir: str = "/var/log/netsentry/logs"  # one YYYY-MM-DD.log per day; empty: disabled
    daily_log_check: int = 1800      # seconds between "server all good" / unapproved device checks
    keep_events_days: int = 180
    oui_file: str = ""               # empty: use the first vendor database found on the system


@dataclass
class NtfyConfig:
    url: str = ""
    token: str = ""


@dataclass
class EmailConfig:
    host: str = ""
    port: int = 587
    security: str = "starttls"       # starttls, ssl or none
    username: str = ""
    password: str = ""
    sender: str = ""
    recipients: List[str] = field(default_factory=list)


@dataclass
class WebhookConfig:
    url: str = ""
    format: str = "generic"          # generic, slack or discord


@dataclass
class Config:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)


def load_config(path: str, required: bool = True) -> Config:
    """Load *path*. When it is missing and not *required*, the built-in defaults are used."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as fh:
            parser.read_file(fh)
    except FileNotFoundError:
        if required:
            raise ConfigError(f"config file not found: {path}")
        return Config()
    except configparser.Error as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    cfg = Config()
    sections = {f.name: getattr(cfg, f.name) for f in fields(cfg)}
    for name in parser.sections():
        if name not in sections:
            raise ConfigError(f"{path}: unknown section [{name}]")
        _fill(sections[name], parser[name], f"{path} [{name}]")
    _validate(cfg)
    return cfg


def _fill(target, section: configparser.SectionProxy, where: str) -> None:
    known = {f.name for f in fields(target)}
    for key in section:
        if key not in known:
            raise ConfigError(f"{where}: unknown option '{key}'")
        default = getattr(target, key)
        try:
            if isinstance(default, bool):
                value = section.getboolean(key)
            elif isinstance(default, int):
                value = section.getint(key)
            elif isinstance(default, float):
                value = section.getfloat(key)
            elif isinstance(default, list):
                value = [item.strip() for item in section[key].split(",") if item.strip()]
            else:
                value = section[key].strip()
        except ValueError as exc:
            raise ConfigError(f"{where}: bad value for '{key}': {exc}") from exc
        setattr(target, key, value)


def _validate(cfg: Config) -> None:
    checks = [
        (cfg.general.log_level.upper() in LOG_LEVELS, f"[general] log_level must be one of {', '.join(LOG_LEVELS)}"),
        (cfg.general.min_severity in SEVERITIES, f"[general] min_severity must be one of {', '.join(SEVERITIES)}"),
        (cfg.scan.interval >= 10, "[scan] interval must be at least 10 seconds"),
        (cfg.scan.timeout > 0, "[scan] timeout must be positive"),
        (cfg.scan.passes >= 1, "[scan] passes must be at least 1"),
        (cfg.scan.max_hosts >= 1, "[scan] max_hosts must be at least 1"),
        (cfg.detection.offline_after >= cfg.scan.interval, "[detection] offline_after must be >= [scan] interval"),
        (cfg.storage.daily_log_check >= cfg.scan.interval, "[storage] daily_log_check must be >= [scan] interval"),
        (cfg.storage.keep_events_days >= 1, "[storage] keep_events_days must be at least 1"),
        (cfg.email.security in ("starttls", "ssl", "none"), "[email] security must be starttls, ssl or none"),
        (1 <= cfg.email.port <= 65535, "[email] port must be between 1 and 65535"),
        (not cfg.email.host or bool(cfg.email.sender and cfg.email.recipients),
         "[email] sender and recipients are required when host is set"),
        (cfg.webhook.format in ("generic", "slack", "discord"), "[webhook] format must be generic, slack or discord"),
    ]
    for ok, message in checks:
        if not ok:
            raise ConfigError(message)
    cfg.general.log_level = cfg.general.log_level.upper()
    if cfg.scan.subnet:
        try:
            ipaddress.IPv4Network(cfg.scan.subnet, strict=False)
        except ValueError as exc:
            raise ConfigError(f"[scan] subnet: {exc}") from exc
