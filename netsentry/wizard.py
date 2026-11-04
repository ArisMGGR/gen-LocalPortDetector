"""Interactive setup: `sudo netsentry setup` asks a few questions, writes the config and starts the service."""
from __future__ import annotations

import copy
import getpass
import ipaddress
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .config import DEFAULT_CONFIG_PATH, Config, ConfigError, load_config
from .netutil import resolve_interface
from .notify import EmailChannel, NtfyChannel, WebhookChannel, summarize
from .store import Event

UNIT_PATH = "/etc/systemd/system/netsentry.service"
SECRET_OPTIONS = {("ntfy", "token"), ("email", "password")}
EMAIL_PORTS = {"starttls": 587, "ssl": 465, "none": 25}
_SECTION_RE = re.compile(r"\s*\[([^\]]+)\]\s*$")
_OPTION_RE = re.compile(r"([A-Za-z0-9_]+)\s*[=:]")
_NTFY_TOPIC_RE = re.compile(r"[-_A-Za-z0-9]{1,64}")

Changes = Dict[str, Dict[str, str]]


def update_config_text(text: str, changes: Changes) -> str:
    """Set options in INI *text*, keeping comments and layout. Missing options and sections are added."""
    pending = {section: dict(options) for section, options in changes.items()}
    out: List[str] = []
    section: Optional[str] = None
    anchor = -1             # index in *out* after which missing options of the current section go
    in_continuation = False  # dropping the indented continuation lines of a replaced value
    in_value = False         # keeping the indented continuation lines of an unchanged value

    def close_section() -> None:
        missing = pending.pop(section, None) if section else None
        if missing:
            out[anchor + 1:anchor + 1] = [f"{key} = {value}" for key, value in missing.items()]

    for line in text.splitlines():
        header = _SECTION_RE.match(line)
        if header:
            close_section()
            section = header.group(1).strip()
            out.append(line)
            anchor = len(out) - 1
            in_continuation = in_value = False
            continue
        continuation = line[:1].isspace() and line.strip() and not line.lstrip().startswith(("#", ";"))
        if in_continuation and continuation:
            continue
        in_continuation = False
        if in_value and continuation:
            out.append(line)
            anchor = len(out) - 1
            continue
        in_value = False
        option = _OPTION_RE.match(line)
        if option and section is not None:
            key = option.group(1).lower()
            if key in pending.get(section, {}):
                out.append(f"{key} = {pending[section].pop(key)}")
                in_continuation = True
            else:
                out.append(line)
                in_value = True
            anchor = len(out) - 1
            continue
        out.append(line)
    close_section()

    for name, options in pending.items():
        if options:
            if out and out[-1].strip():
                out.append("")
            out.append(f"[{name}]")
            out.extend(f"{key} = {value}" for key, value in options.items())
    return "\n".join(out) + "\n"


def _ini_value(value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(value)
    return str(value)


def _check_url(value: str) -> Optional[str]:
    parts = urlsplit(value)
    if parts.scheme in ("http", "https") and parts.netloc:
        return None
    return "enter a full URL starting with https://"


def _check_required(value: str) -> Optional[str]:
    return None if value else "this is required"


def _check_email_list(value: str) -> Optional[str]:
    addresses = [a.strip() for a in value.split(",") if a.strip()]
    if addresses and all("@" in a for a in addresses):
        return None
    return "enter one or more email addresses, separated by commas"


class Wizard:
    def __init__(self, path: str, cfg: Config, preview: Optional[Callable[[Config], int]] = None,
                 input_fn: Callable[[str], str] = input, password_fn: Callable[[str], str] = getpass.getpass,
                 out=sys.stdout):
        self.path = path
        self.cfg = cfg                       # working copy, updated as answers come in
        self.original = copy.deepcopy(cfg)   # what the file says now
        self.changes: Changes = {}
        self.preview = preview
        self.input = input_fn
        self.password = password_fn
        self.out = out
        self.saved = False

    # -- prompts ---------------------------------------------------------------------------

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def ask(self, prompt: str, default: str = "", check: Optional[Callable[[str], Optional[str]]] = None) -> str:
        suffix = f" [{default}]" if default else ""
        while True:
            answer = self.input(f"{prompt}{suffix}: ").strip() or default
            error = check(answer) if check else None
            if error is None:
                return answer
            self.say(f"  {error}")

    def yes_no(self, prompt: str, default: bool) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            answer = self.input(f"{prompt} [{hint}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.say("  please answer y or n")

    def choose(self, prompt: str, options: List[Tuple[str, str]], default: str) -> str:
        """Numbered menu of (value, label) pairs; returns the chosen value."""
        self.say(prompt)
        for i, (value, label) in enumerate(options, 1):
            self.say(f"  {i}) {label}")
        values = [value for value, _ in options]
        default_number = str(values.index(default) + 1)
        while True:
            answer = self.input(f"Choice [{default_number}]: ").strip() or default_number
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return values[int(answer) - 1]
            if answer in values:
                return answer
            self.say(f"  enter a number from 1 to {len(options)}")

    def secret(self, prompt: str, current: str) -> str:
        hint = " (Enter keeps the current one, '-' removes it)" if current else " (Enter for none)"
        answer = self.password(f"{prompt}{hint}: ").strip()
        if not answer:
            return current
        return "" if answer == "-" else answer

    def set(self, section: str, key: str, value) -> None:
        setattr(getattr(self.cfg, section), key, value)
        if getattr(getattr(self.original, section), key) == value:
            self.changes.get(section, {}).pop(key, None)
        else:
            self.changes.setdefault(section, {})[key] = _ini_value(value)

    # -- flow ------------------------------------------------------------------------------

    def run(self) -> int:
        target = self.path if os.path.exists(self.path) else os.path.dirname(os.path.abspath(self.path))
        if not os.access(target, os.W_OK):
            raise RuntimeError(f"cannot write {self.path}; run setup with sudo")
        self.say("netsentry setup. Press Enter to accept the [default] answer, Ctrl+C to quit without saving.")
        self.say()
        self.step_network()
        self.step_notifications()
        self.step_alerts()
        if not self.step_save():
            return 0
        self.step_preview()
        return self.step_service()

    def step_network(self) -> None:
        self.say("== Network ==")
        try:
            iface = resolve_interface(self.cfg.scan.interface, self.cfg.scan.subnet)
        except (OSError, RuntimeError, ValueError) as exc:
            self.say(f"Could not detect the network to watch: {exc}")
            iface = None
        if iface is not None:
            gateway = f", router {iface.gateway}" if iface.gateway else ""
            self.say(f"Detected {iface.network} on {iface.name} (this machine is {iface.ip}{gateway}).")
            if self.yes_no("Watch this network?", True):
                self.say()
                return

        names = sorted(n for n in os.listdir("/sys/class/net") if n != "lo") if os.path.isdir("/sys/class/net") else []
        while True:
            name = self.ask(f"Interface to watch ({', '.join(names) or 'none found'})",
                            iface.name if iface else "", check=_check_required)
            try:
                chosen = resolve_interface(name)
                break
            except (OSError, RuntimeError, ValueError) as exc:
                self.say(f"  {exc}")
        subnet = self.ask("Subnet to sweep", str(chosen.network),
                          check=lambda v: None if _is_network(v) else "enter a subnet like 192.168.1.0/24")
        self.set("scan", "interface", name)
        network = ipaddress.IPv4Network(subnet, strict=False)
        self.set("scan", "subnet", "" if network == chosen.network else str(network))
        self.say()

    def step_notifications(self) -> None:
        self.say("== Notifications ==")
        self.say("Choose how netsentry should reach you. You can set up more than one.")
        setups = {"ntfy": self.setup_ntfy, "webhook": self.setup_webhook, "email": self.setup_email}
        while True:
            options = [
                ("ntfy", "Phone push notifications with the free ntfy app" + self._status("ntfy")),
                ("webhook", "Slack, Discord or another webhook" + self._status("webhook")),
                ("email", "Email" + self._status("email")),
                ("done", "Done"),
            ]
            default = "done" if self._configured_channels() else "ntfy"
            choice = self.choose("Set up a channel:", options, default)
            if choice == "done":
                if self._configured_channels() or self.yes_no(
                        "No channel is set up, so alerts will only reach the system log. Continue anyway?", False):
                    break
                continue
            if self._configured(choice):
                action = self.choose(f"{choice} is on.", [("change", "Change its settings"),
                                                          ("off", "Turn it off"), ("back", "Leave it as it is")], "back")
                if action == "off":
                    self.set(choice, "host" if choice == "email" else "url", "")
                if action != "change":
                    continue
            while True:
                channel = setups[choice]()
                if self.test_channel(channel) or not self.yes_no("Change the settings and try again?", True):
                    break
        self.say()

    def setup_ntfy(self) -> NtfyChannel:
        server, topic = "https://ntfy.sh", ""
        if self.cfg.ntfy.url:
            parts = urlsplit(self.cfg.ntfy.url)
            server, topic = f"{parts.scheme}://{parts.netloc}", parts.path.strip("/")
        self.say("Anyone who knows the topic name can read your alerts, so the suggested one is random.")
        server = self.ask("ntfy server", server, check=_check_url).rstrip("/")
        topic = self.ask("Topic", topic or f"netsentry-{secrets.token_hex(8)}",
                         check=lambda v: None if _NTFY_TOPIC_RE.fullmatch(v) else
                         "use up to 64 letters, digits, '-' or '_'")
        token = self.secret("Access token, only needed for protected topics", self.cfg.ntfy.token)
        self.set("ntfy", "url", f"{server}/{topic}")
        self.set("ntfy", "token", token)
        self.say(f"Install the ntfy app on your phone, tap '+' and subscribe to the topic: {topic}")
        if server != "https://ntfy.sh":
            self.say(f"(Turn on 'Use another server' and enter {server}.)")
        self.input("Press Enter once you have subscribed... ")
        return NtfyChannel(self.cfg.ntfy)

    def setup_webhook(self) -> WebhookChannel:
        url = self.ask("Webhook URL", self.cfg.webhook.url, check=_check_url)
        if "hooks.slack.com" in url:
            guess = "slack"
        elif "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
            guess = "discord"
        else:
            guess = self.cfg.webhook.format
        fmt = self.choose("Message format:", [("slack", "Slack"), ("discord", "Discord"),
                                              ("generic", "Generic JSON")], guess)
        self.set("webhook", "url", url)
        self.set("webhook", "format", fmt)
        return WebhookChannel(self.cfg.webhook)

    def setup_email(self) -> EmailChannel:
        email = self.cfg.email
        host = self.ask("SMTP server, e.g. smtp.gmail.com", email.host, check=_check_required)
        security = self.choose("Connection security:", [("starttls", "STARTTLS (usually port 587)"),
                                                        ("ssl", "SSL/TLS (usually port 465)"),
                                                        ("none", "None (not recommended)")], email.security)
        port_default = email.port if security == email.security else EMAIL_PORTS[security]
        port = self.ask("Port", str(port_default),
                        check=lambda v: None if v.isdigit() and 0 < int(v) < 65536 else "enter a port number")
        username = self.ask("Username (Enter if the server needs no login)", email.username)
        password = self.secret("Password (for Gmail and similar, an app password)", email.password) if username else ""
        sender = self.ask("From address", email.sender or (username if "@" in username else ""),
                          check=_check_email_list)
        recipients = self.ask("Send alerts to (comma-separated)", ", ".join(email.recipients) or sender,
                              check=_check_email_list)
        self.set("email", "host", host)
        self.set("email", "security", security)
        self.set("email", "port", int(port))
        self.set("email", "username", username)
        self.set("email", "password", password)
        self.set("email", "sender", sender)
        self.set("email", "recipients", [a.strip() for a in recipients.split(",") if a.strip()])
        return EmailChannel(self.cfg.email)

    def test_channel(self, channel) -> bool:
        if not self.yes_no("Send a test notification now?", True):
            return True
        event = Event("test", "warning", "This is a test alert from netsentry setup. If you can read it, "
                                         "notifications work.")
        title, body, severity = summarize([event], socket.gethostname())
        try:
            channel.send(title, body, severity, [event])
        except Exception as exc:  # any delivery problem is reported, never fatal
            self.say(f"  Sending failed: {exc}")
            return False
        return self.yes_no("Sent. Did it arrive?", True)

    def step_alerts(self) -> None:
        self.say("== Alerts ==")
        was_chatty = self.cfg.general.min_severity == "info"
        chatty = self.yes_no("Also notify you when known devices come online, go offline or change IP?", was_chatty)
        if chatty != was_chatty:  # keep a hand-set min_severity (e.g. critical) unless the answer changes
            self.set("general", "min_severity", "info" if chatty else "warning")
        if not os.path.exists(self.cfg.storage.database):
            self.say("On its first scan netsentry can record every device already on the network as trusted.")
            self.say("Say no if you suspect something unwanted is connected: every device will then alert as new")
            self.say("and you approve them one by one with 'sudo netsentry approve'.")
            self.set("detection", "baseline_on_first_run",
                     self.yes_no("Trust the devices that are on the network right now?",
                                 self.cfg.detection.baseline_on_first_run))
        self.say()

    def step_save(self) -> bool:
        changes = {s: o for s, o in self.changes.items() if o}
        if not changes:
            self.say(f"No changes; {self.path} is left as it is.")
            return True
        self.say("== Summary ==")
        for section, options in changes.items():
            for key, value in options.items():
                shown = ("(set)" if value else "(none)") if (section, key) in SECRET_OPTIONS else value or "(empty)"
                self.say(f"  [{section}] {key} = {shown}")
        if not self.yes_no(f"Save these settings to {self.path}?", True):
            self.say("Nothing was saved.")
            return False
        text = ""
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as fh:
                text = fh.read()
        self.cfg = self._write(update_config_text(text, changes))
        self.saved = True
        self.say(f"Saved {self.path}.")
        self.say()
        return True

    def _write(self, text: str) -> Config:
        """Write *text* atomically, keeping the old file's owner and mode; refuses a config the daemon would reject."""
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(prefix=".netsentry-", suffix=".conf", dir=directory)  # created 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            try:
                cfg = load_config(tmp)
            except ConfigError as exc:
                raise RuntimeError(f"nothing saved; fix {self.path} by hand first: "
                                   f"{str(exc).replace(tmp, self.path)}") from exc
            if os.path.exists(self.path):
                st = os.stat(self.path)
                os.chmod(tmp, st.st_mode & 0o7777)
                if hasattr(os, "chown"):
                    os.chown(tmp, st.st_uid, st.st_gid)
            else:
                # Same owner and mode as install.sh gives it, so the service user can read it.
                os.chmod(tmp, 0o640)
                try:
                    import grp  # Linux only
                    os.chown(tmp, -1, grp.getgrnam("netsentry").gr_gid)
                except (ImportError, KeyError):
                    pass
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return cfg

    def step_preview(self) -> None:
        if self.preview is None or not self.yes_no("Run a quick scan now to see what is on your network?", True):
            return
        try:
            self.preview(self.cfg)
        except PermissionError:
            self.say("  The scan needs root; run setup with sudo to see it.")
        except (OSError, RuntimeError, ValueError) as exc:
            self.say(f"  Scan failed: {exc}")
        self.say()

    def step_service(self) -> int:
        if os.path.abspath(self.path) != DEFAULT_CONFIG_PATH or not shutil.which("systemctl") \
                or not os.path.exists(UNIT_PATH):
            self.say(f"The netsentry service is not installed for this config. Run it with: "
                     f"sudo netsentry -c {self.path} run")
            return 0
        running = subprocess.run(["systemctl", "is-active", "--quiet", "netsentry"]).returncode == 0
        prompt = "Restart netsentry to apply the new settings?" if running else "Start netsentry now and on every boot?"
        if not self.yes_no(prompt, True):
            self.say("Start it later with: sudo systemctl enable --now netsentry")
            return 0
        subprocess.run(["systemctl", "enable", "--quiet", "netsentry"], check=False)
        result = subprocess.run(["systemctl", "restart", "netsentry"])
        if result.returncode != 0:
            self.say("netsentry failed to start. See why with: journalctl -u netsentry -n 50")
            return 1
        self.say("netsentry is running and will start on every boot.")
        self.say()
        self.say("Next:")
        self.say("  sudo netsentry list            devices it has found (name the ones you recognise)")
        self.say("  journalctl -u netsentry -f     follow the log")
        self.say("  sudo netsentry setup           change these settings at any time")
        return 0

    # -- helpers ---------------------------------------------------------------------------

    def _configured(self, channel: str) -> bool:
        return bool(self.cfg.email.host if channel == "email" else getattr(self.cfg, channel).url)

    def _configured_channels(self) -> List[str]:
        return [c for c in ("ntfy", "webhook", "email") if self._configured(c)]

    def _status(self, channel: str) -> str:
        if not self._configured(channel):
            return ""
        if channel == "email":
            return f"  [on: to {', '.join(self.cfg.email.recipients)}]"
        return f"  [on: {urlsplit(getattr(self.cfg, channel).url).netloc}]"


def _is_network(value: str) -> bool:
    try:
        ipaddress.IPv4Network(value, strict=False)
        return True
    except ValueError:
        return False
