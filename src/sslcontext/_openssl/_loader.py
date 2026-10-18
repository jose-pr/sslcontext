"""Find the libssl and libcrypto that the running interpreter's ``_ssl`` loaded.

Objects created by one copy of libcrypto must never reach another (separate
heaps, separate method stores), so the libraries are located among the modules
already mapped into the process, never by name on a search path.
"""

from __future__ import annotations

import ctypes
import os
import ssl
import sys

from ..exceptions import UnsupportedOpenSSLError

__all__ = ["find_libraries"]


def _loaded_paths() -> list[str]:
    if sys.platform == "win32":
        return _windows_modules()
    if sys.platform == "darwin":
        return _dyld_images()
    return _proc_maps()


def _windows_modules() -> list[str]:
    from ctypes import wintypes

    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.EnumProcessModules.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HMODULE),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    psapi.GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE,
        wintypes.HMODULE,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    process = kernel32.GetCurrentProcess()
    count = 256
    while True:
        modules = (wintypes.HMODULE * count)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModules(
            process, modules, ctypes.sizeof(modules), ctypes.byref(needed)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if needed.value <= ctypes.sizeof(modules):
            break
        count = needed.value // ctypes.sizeof(wintypes.HMODULE) + 16
    paths = []
    buffer = ctypes.create_unicode_buffer(32768)
    for module in modules[: needed.value // ctypes.sizeof(wintypes.HMODULE)]:
        if psapi.GetModuleFileNameExW(process, module, buffer, len(buffer)):
            paths.append(buffer.value)
    return paths


def _proc_maps() -> list[str]:
    paths = []
    with open("/proc/self/maps", encoding="utf-8", errors="replace") as maps:
        for line in maps:
            parts = line.split(None, 5)
            if len(parts) == 6 and parts[5].startswith("/"):
                paths.append(parts[5].strip())
    return paths


def _dyld_images() -> list[str]:
    libc = ctypes.CDLL(None)
    libc._dyld_image_count.restype = ctypes.c_uint32
    libc._dyld_get_image_name.restype = ctypes.c_char_p
    libc._dyld_get_image_name.argtypes = [ctypes.c_uint32]
    return [
        libc._dyld_get_image_name(i).decode("utf-8", "replace")
        for i in range(libc._dyld_image_count())
    ]


def _pick(paths: list[str], stem: str) -> str | None:
    # libcrypto-3-arm64.dll, libcrypto-1_1.dll, libcrypto.so.3, libcrypto.3.dylib
    for path in paths:
        name = os.path.basename(path).lower()
        if name.startswith(stem) and (
            name.endswith(".dll") or ".so" in name or name.endswith(".dylib")
        ):
            return path
    return None


def find_libraries() -> tuple[ctypes.CDLL, ctypes.CDLL]:
    """Return ``(libssl, libcrypto)`` as loaded by :mod:`ssl`.

    Raises :class:`UnsupportedOpenSSLError` when the interpreter links an
    OpenSSL these bindings cannot reach (LibreSSL, a static build).
    """
    import _ssl  # noqa: F401  (maps the libraries into the process)

    if ssl.OPENSSL_VERSION.startswith("LibreSSL"):
        raise UnsupportedOpenSSLError(
            f"{ssl.OPENSSL_VERSION} is not supported; sslcontext needs OpenSSL 1.1.1 or 3.x"
        )
    paths = _loaded_paths()
    ssl_path, crypto_path = _pick(paths, "libssl"), _pick(paths, "libcrypto")
    if ssl_path and crypto_path:
        libssl, libcrypto = ctypes.CDLL(ssl_path), ctypes.CDLL(crypto_path)
    else:
        # A statically linked _ssl exports OpenSSL from its own module, if at all.
        module = ctypes.CDLL(_ssl.__file__)
        if not hasattr(module, "SSL_CTX_new") or not hasattr(module, "EVP_PKEY_new"):
            raise UnsupportedOpenSSLError(
                "the interpreter's OpenSSL is linked statically and does not export its symbols"
            )
        libssl = libcrypto = module
    libcrypto.OpenSSL_version_num.restype = ctypes.c_ulong
    if libcrypto.OpenSSL_version_num() != ssl.OPENSSL_VERSION_NUMBER:
        raise UnsupportedOpenSSLError(
            f"found {crypto_path!r}, which is not the OpenSSL the ssl module reports"
        )
    if ssl.OPENSSL_VERSION_INFO < (1, 1, 1):
        raise UnsupportedOpenSSLError(
            f"{ssl.OPENSSL_VERSION} is too old; sslcontext needs OpenSSL 1.1.1 or later"
        )
    return libssl, libcrypto
