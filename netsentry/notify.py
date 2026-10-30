"""Alert delivery: ntfy push notifications, generic/Slack/Discord webhooks and email."""
from __future__ import annotations

import json
import logging
import smtplib
import socket
import ssl
import urllib.request
from dataclasses import asdict
from email.message import EmailMessage
from typing import Dict, List, Tuple

from . import __version__
from .config import SEVERITIES, Config, EmailConfig, NtfyConfig, WebhookConfig
from .store import Event

log = logging.getLogger(__name__)

USER_AGENT = f"netsentry/{__version__}"
TITLES = {
    "new_device": "New device on the network",
    "unapproved_return": "Unapproved device back online",
    "ip_conflict": "Possible ARP spoofing / IP conflict",
    "gateway_change": "Gateway MAC changed: possible man-in-the-middle",
    "baseline": "Monitoring started",
    "test": "Test notification",
}
NTFY_PRIORITY = {"info": "default", "warning": "high", "critical": "urgent"}
NTFY_TAGS = {"info": "information_source", "warning": "warning", "critical": "rotating_light"}


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def summarize(events: List[Event], host: str) -> Tuple[str, str, str]:
    """Collapse a batch of events into one (title, body, worst severity) message."""
    worst = max((e.severity for e in events), key=severity_rank)
    if len(events) == 1:
        title = TITLES.get(events[0].kind, events[0].kind.replace("_", " ").capitalize())
        body = events[0].message
    else:
        title = f"{len(events)} network alerts"
        body = "\n".join(f"- {e.message}" for e in events)
    return f"[{host}] {title}", body, worst


def _post(url: str, data: bytes, headers: Dict[str, str]) -> None:
    request = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **headers}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


class NtfyChannel:
    name = "ntfy"

    def __init__(self, cfg: NtfyConfig):
        self.cfg = cfg

    def send(self, title: str, body: str, severity: str, events: List[Event]) -> None:
        headers = {"Title": title, "Priority": NTFY_PRIORITY[severity], "Tags": NTFY_TAGS[severity]}
        if self.cfg.token:
            headers["Authorization"] = f"Bearer {self.cfg.token}"
        _post(self.cfg.url, body.encode(), headers)


class WebhookChannel:
    name = "webhook"

    def __init__(self, cfg: WebhookConfig):
        self.cfg = cfg

    def send(self, title: str, body: str, severity: str, events: List[Event]) -> None:
        if self.cfg.format == "slack":
            payload: dict = {"text": f"*{title}*\n{body}"}
        elif self.cfg.format == "discord":
            payload = {"content": f"**{title}**\n{body}"[:2000]}
        else:
            payload = {"title": title, "severity": severity, "message": body,
                       "events": [asdict(e) for e in events]}
        _post(self.cfg.url, json.dumps(payload).encode(), {"Content-Type": "application/json"})


class EmailChannel:
    name = "email"

    def __init__(self, cfg: EmailConfig):
        self.cfg = cfg

    def send(self, title: str, body: str, severity: str, events: List[Event]) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"[{severity.upper()}] {title}"
        msg["From"] = self.cfg.sender
        msg["To"] = ", ".join(self.cfg.recipients)
        msg.set_content(body)
        context = ssl.create_default_context()
        if self.cfg.security == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(self.cfg.host, self.cfg.port, timeout=15, context=context)
        else:
            smtp = smtplib.SMTP(self.cfg.host, self.cfg.port, timeout=15)
        with smtp:
            if self.cfg.security == "starttls":
                smtp.starttls(context=context)
            if self.cfg.username:
                smtp.login(self.cfg.username, self.cfg.password)
            smtp.send_message(msg)


class Notifier:
    def __init__(self, cfg: Config):
        self.min_rank = severity_rank(cfg.general.min_severity)
        self.host = socket.gethostname()
        self.channels: list = []
        if cfg.ntfy.url:
            self.channels.append(NtfyChannel(cfg.ntfy))
        if cfg.webhook.url:
            self.channels.append(WebhookChannel(cfg.webhook))
        if cfg.email.host:
            self.channels.append(EmailChannel(cfg.email))

    def send(self, events: List[Event], force: bool = False) -> int:
        """Send events at or above min_severity as one message per channel; returns the failure count."""
        selected = events if force else [e for e in events if severity_rank(e.severity) >= self.min_rank]
        if not selected or not self.channels:
            return 0
        title, body, severity = summarize(selected, self.host)
        failures = 0
        for channel in self.channels:
            try:
                channel.send(title, body, severity, selected)
            except Exception as exc:  # a broken channel must never stop monitoring
                failures += 1
                log.error("%s notification failed: %s", channel.name, exc)
        return failures
