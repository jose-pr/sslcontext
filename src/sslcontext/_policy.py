"""The browsers' ``AutoSelectCertificateForUrls`` policy, read where they read it.

Each entry is a JSON object, ``{"pattern": "https://[*.]example.com",
"filter": {"ISSUER": {"CN": "Corp CA"}, "SUBJECT": {"OU": "Staff"}}}``, set by
an administrator for Chrome, Chromium or Edge: the registry on Windows,
managed JSON files on Linux, managed preferences on macOS.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import plistlib
import sys
from typing import Iterable, Iterator, List, Mapping, Union

from ._select import AutoSelectRule

__all__ = ["browser_policies", "rules_from_policy"]

_log = logging.getLogger("sslcontext")
_POLICY = "AutoSelectCertificateForUrls"
_REGISTRY_KEYS = (
    r"SOFTWARE\Policies\Microsoft\Edge",
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Chromium",
)
_POLICY_DIRS = (
    "/etc/opt/edge/policies/managed",
    "/etc/opt/chrome/policies/managed",
    "/etc/chromium/policies/managed",
)
_PLIST_GLOBS = (
    "/Library/Managed Preferences/com.microsoft.Edge.plist",
    "/Library/Managed Preferences/com.google.Chrome.plist",
    "/Library/Managed Preferences/org.chromium.Chromium.plist",
    "/Library/Managed Preferences/*/com.microsoft.Edge.plist",
    "/Library/Managed Preferences/*/com.google.Chrome.plist",
    "/Library/Managed Preferences/*/org.chromium.Chromium.plist",
)


def _filter(spec: object) -> Union[Mapping[str, str], None]:
    if not spec:
        return None
    if not isinstance(spec, dict):
        raise ValueError("a filter is an object of attributes")
    out = {}
    for attribute, value in spec.items():
        if isinstance(value, list):  # several values: each must be present
            if len(value) != 1:
                raise ValueError("only one value per attribute is supported")
            value = value[0]
        if not isinstance(value, str):
            raise ValueError(f"{attribute} must be a string")
        out[str(attribute).upper()] = value
    return out


def rules_from_policy(entries: Iterable[Union[str, Mapping]]) -> List[AutoSelectRule]:
    """Rules from policy entries (JSON text or decoded objects), in order.
    A malformed entry is logged and skipped, as the browsers skip it."""
    rules = []
    for entry in entries:
        try:
            value = json.loads(entry) if isinstance(entry, str) else entry
            if not isinstance(value, Mapping) or not isinstance(
                value.get("pattern"), str
            ):
                raise ValueError("an entry needs a pattern")
            spec = value.get("filter") or {}
            if not isinstance(spec, Mapping):
                raise ValueError("filter must be an object")
            rules.append(
                AutoSelectRule(
                    value["pattern"],
                    issuer=_filter(spec.get("ISSUER")),
                    subject=_filter(spec.get("SUBJECT")),
                )
            )
        except ValueError as error:
            _log.debug("sslcontext: skipping policy entry %r: %s", entry, error)
    return rules


def _registry_entries() -> Iterator[str]:
    import winreg

    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for base in _REGISTRY_KEYS:
            try:
                key = winreg.OpenKey(hive, base + "\\" + _POLICY)
            except OSError:
                continue
            with key:
                values = []
                index = 0
                while True:
                    try:
                        name, value, kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if kind == winreg.REG_SZ and isinstance(value, str):
                        values.append((_order(name), value))
                yield from (value for _, value in sorted(values))


def _order(name: str) -> tuple:
    return (0, int(name), "") if name.isdigit() else (1, 0, name)


def _json_entries() -> Iterator[object]:
    for directory in _POLICY_DIRS:
        for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
            try:
                with open(path, encoding="utf-8") as handle:
                    document = json.load(handle)
            except (OSError, ValueError) as error:
                _log.debug("sslcontext: cannot read %s: %s", path, error)
                continue
            values = document.get(_POLICY) if isinstance(document, dict) else None
            if isinstance(values, list):
                yield from values


def _plist_entries() -> Iterator[object]:
    for pattern in _PLIST_GLOBS:
        for path in sorted(glob.glob(pattern)):
            try:
                with open(path, "rb") as handle:
                    document = plistlib.load(handle)
            except (OSError, ValueError, plistlib.InvalidFileException) as error:
                _log.debug("sslcontext: cannot read %s: %s", path, error)
                continue
            values = document.get(_POLICY) if isinstance(document, dict) else None
            if isinstance(values, list):
                yield from values


def browser_policies() -> List[AutoSelectRule]:
    """The ``AutoSelectCertificateForUrls`` rules set for Edge, Chrome and
    Chromium on this machine, machine-wide before per-user, in each
    browser's order. Empty when none is set; never raises for a policy that
    cannot be read."""
    if sys.platform == "win32":
        entries: Iterable = _registry_entries()
    elif sys.platform == "darwin":
        entries = _plist_entries()
    else:
        entries = _json_entries()
    try:
        return rules_from_policy(list(entries))
    except OSError as error:
        _log.debug("sslcontext: cannot read the browser policies: %s", error)
        return []
