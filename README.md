# NullSec NimHunter

**Memory Forensics Scanner** written in Nim

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-nimhunter/releases)
[![Language](https://img.shields.io/badge/language-Nim-ffe953.svg)](https://nim-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Discord: [discord.gg/killers](https://discord.gg/killers)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

NimHunter is a memory forensics scanner that detects malicious code patterns, shellcode signatures, and injection artifacts in process memory. Built with Nim's compile-time metaprogramming and zero-overhead abstractions for high-performance memory analysis.

## Nim Features Showcased

- **Compile-time Metaprogramming**: Templates and macros
- **Strong Type System**: Object variants, enums
- **Zero-overhead Abstractions**: C-level performance
- **FFI Capabilities**: Native OS API integration
- **Iterators**: Custom iteration patterns
- **Proc Types**: Higher-order functions
- **seq/Table Types**: Dynamic collections

## Detection Signatures

| Pattern | Risk | MITRE | Description |
|---------|------|-------|-------------|
| Metasploit Meterpreter | CRITICAL | T1055 | Meterpreter PE header |
| Cobalt Strike Beacon | CRITICAL | T1071 | Beacon shellcode |
| Reflective DLL Loader | CRITICAL | T1620 | Reflective loader sig |
| Process Hollowing | HIGH | T1055.012 | Hollowing prologue |
| NOP Sled | HIGH | T1620 | Shellcode padding |
| API Hashing (ROR13) | HIGH | T1027 | Name hash obfuscation |
| CreateRemoteThread | HIGH | T1055.001 | Thread injection |
| PowerShell in Memory | HIGH | T1059.001 | PS invocation |
| Syscall Stub | MEDIUM | T1106 | Direct syscall |
| Anti-Debug PEB | MEDIUM | T1622 | Debugger check |
| WMI Execution | MEDIUM | T1047 | WMI command |
| Registry Run Key | MEDIUM | T1547.001 | Persistence ref |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-nimhunter.git
cd nullsec-nimhunter

# Build (requires Nim compiler)
nim c -d:release nimhunter.nim

# Run
./nimhunter
```

## Usage

```bash
# Scan a process by PID
./nimhunter -p 1234

# Run demo mode
./nimhunter --demo

# Dump suspicious regions
./nimhunter -p 1234 -d

# Use custom YARA rules
./nimhunter -p 1234 -y rules.yar
```

### Options

```
USAGE:
    nimhunter [OPTIONS] <PID>

OPTIONS:
    -h, --help       Show help
    -p, --pid        Process ID to scan
    -d, --dump       Dump suspicious regions
    -y, --yara       Custom YARA rules file
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║          NullSec NimHunter - Memory Forensics Scanner           ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Scanning process memory for malicious patterns...

  [CRITICAL] Metasploit Meterpreter
    Region:      suspicious.dll
    Address:     0x00007FFE00000000
    Offset:      +0x0
    Permissions: RX
    MITRE:       T1055
    Context:     4D 5A 90 00 03 00 00 00 00 00 00 00 FF FF 00 00

  [CRITICAL] Reflective DLL Loader
    Region:      loader.exe
    Address:     0x0000000040000000
    Offset:      +0x0
    Permissions: RX
    MITRE:       T1620
    Context:     4D 5A 41 52 55 48 89 E5 64 A1 30 00 00 00 00 00

  [HIGH] Shellcode NOP Sled
    Region:      suspicious.dll
    Address:     0x00007FFE00000000
    Offset:      +0x10
    Permissions: RX
    MITRE:       T1620
    Context:     90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90

  [HIGH] PowerShell Download
    Region:      config.data
    Address:     0x0000000020000000
    Offset:      +0x0
    Permissions: RW
    MITRE:       T1059.001
    Context:     70 6F 77 65 72 73 68 65 6C 6C 20 2D 45 78 65 63

═══════════════════════════════════════════

  Summary:
    Regions Scanned: 5
    Findings:        8
    Critical:        2
    High:            4
    Medium:          2
```

## Code Highlights

### Type Definitions
```nim
type RiskLevel = enum
  rlCritical = "CRITICAL"
  rlHigh = "HIGH"
  rlMedium = "MEDIUM"
  rlLow = "LOW"

type MemoryRegion = object
  baseAddress: uint64
  size: uint64
  regionType: MemoryRegionType
  permissions: string
  content: seq[byte]

type SuspiciousPattern = object
  name: string
  pattern: seq[byte]
  description: string
  mitre: string
  risk: RiskLevel
```

### Pattern Matching
```nim
proc findPattern(data: seq[byte], pattern: seq[byte]): seq[int] =
  result = @[]
  for i in 0 .. data.len - pattern.len:
    var found = true
    for j in 0 ..< pattern.len:
      if data[i + j] != pattern[j]:
        found = false
        break
    if found:
      result.add(i)
```

### Region Scanning
```nim
proc scanRegion(region: MemoryRegion, 
                patterns: seq[SuspiciousPattern]): seq[MemoryFinding] =
  result = @[]
  for pattern in patterns:
    let matches = findPattern(region.content, pattern.pattern)
    for offset in matches:
      result.add(MemoryFinding(
        region: region,
        pattern: pattern,
        offset: uint64(offset)
      ))
```

### Functional Processing
```nim
let critical = findings.filterIt(it.pattern.risk == rlCritical).len

allFindings.sort(proc(a, b: MemoryFinding): int =
  result = ord(a.pattern.risk) - ord(b.pattern.risk)
)
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                   NimHunter Architecture                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│    │   Process   │───▶│   Memory    │───▶│   Region    │      │
│    │   Handle    │    │ Enumeration │    │    List     │      │
│    └─────────────┘    └─────────────┘    └──────┬──────┘      │
│                                                  │             │
│         ┌────────────────────────────────────────┘             │
│         ▼                                                      │
│    ┌──────────────────────────────────────────────────┐       │
│    │               Pattern Database                    │       │
│    │  ┌──────────┐ ┌──────────┐ ┌──────────┐         │       │
│    │  │ Shellcode│ │ Malware  │ │ Strings  │         │       │
│    │  │ Patterns │ │ Sigs     │ │ Patterns │         │       │
│    │  └──────────┘ └──────────┘ └──────────┘         │       │
│    └────────────────────────┬─────────────────────────┘       │
│                             │                                  │
│                             ▼                                  │
│                    ┌─────────────────┐                        │
│                    │  Scan Engine    │                        │
│                    │  (byte match)   │                        │
│                    └────────┬────────┘                        │
│                             ▼                                  │
│                    ┌─────────────────┐                        │
│                    │ Findings Report │                        │
│                    └─────────────────┘                        │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Why Nim?

| Requirement | Nim Advantage |
|-------------|---------------|
| Performance | C-level speed |
| Memory Access | Direct pointers |
| Type Safety | Compile-time checks |
| Metaprogramming | Templates/macros |
| Cross-platform | Windows/Linux/macOS |
| Small Binary | Minimal runtime |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-memgrep](https://github.com/bad-antics/nullsec-memgrep) - Memory search (Go)
- [nullsec-binarydiff](https://github.com/bad-antics/nullsec-binarydiff) - Binary diff (Swift)
- [nullsec-byteforge](https://github.com/bad-antics/nullsec-byteforge) - Payload builder (Kotlin)
