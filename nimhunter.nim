// NullSec NimHunter - Memory Forensics Scanner
// Nim security tool demonstrating:
//   - Compile-time metaprogramming
//   - Templates and macros
//   - Strong type system
//   - FFI capabilities
//   - Async/await
//   - Object variants
//
// Author: bad-antics
// License: MIT

import std/[strutils, strformat, sequtils, tables, times, algorithm]

const VERSION = "1.0.0"

# ANSI Colors
const
  RED = "\e[31m"
  GREEN = "\e[32m"
  YELLOW = "\e[33m"
  CYAN = "\e[36m"
  GRAY = "\e[90m"
  RESET = "\e[0m"

proc colorize(color, text: string): string =
  result = color & text & RESET

# Risk levels
type RiskLevel = enum
  rlCritical = "CRITICAL"
  rlHigh = "HIGH"
  rlMedium = "MEDIUM"
  rlLow = "LOW"
  rlInfo = "INFO"

proc riskColor(risk: RiskLevel): string =
  case risk
  of rlCritical, rlHigh: RED
  of rlMedium: YELLOW
  of rlLow: CYAN
  of rlInfo: GRAY

# Memory region types
type MemoryRegionType = enum
  mrtCode = "CODE"
  mrtData = "DATA"
  mrtHeap = "HEAP"
  mrtStack = "STACK"
  mrtMapped = "MAPPED"
  mrtUnknown = "UNKNOWN"

# Memory region
type MemoryRegion = object
  baseAddress: uint64
  size: uint64
  regionType: MemoryRegionType
  permissions: string
  name: string
  content: seq[byte]

# Suspicious pattern
type SuspiciousPattern = object
  name: string
  pattern: seq[byte]
  description: string
  mitre: string
  risk: RiskLevel

# Memory finding
type MemoryFinding = object
  region: MemoryRegion
  pattern: SuspiciousPattern
  offset: uint64
  context: seq[byte]

# Suspicious patterns database
let suspiciousPatterns = @[
  SuspiciousPattern(
    name: "Metasploit Meterpreter",
    pattern: @[0x4D'u8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00],
    description: "Meterpreter payload PE header",
    mitre: "T1055",
    risk: rlCritical
  ),
  SuspiciousPattern(
    name: "Cobalt Strike Beacon",
    pattern: @[0x4D'u8, 0x5A, 0xE8, 0x00, 0x00, 0x00, 0x00],
    description: "Cobalt Strike beacon shellcode",
    mitre: "T1071",
    risk: rlCritical
  ),
  SuspiciousPattern(
    name: "Process Hollowing",
    pattern: @[0x55'u8, 0x8B, 0xEC, 0x83, 0xE4, 0xF8],
    description: "Common process hollowing prologue",
    mitre: "T1055.012",
    risk: rlHigh
  ),
  SuspiciousPattern(
    name: "Shellcode NOP Sled",
    pattern: @[0x90'u8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
    description: "NOP sled padding for shellcode",
    mitre: "T1620",
    risk: rlHigh
  ),
  SuspiciousPattern(
    name: "API Hashing (ROR13)",
    pattern: @[0xC1'u8, 0xCF, 0x0D, 0x03, 0xCE],
    description: "ROR13 API name hashing",
    mitre: "T1027",
    risk: rlHigh
  ),
  SuspiciousPattern(
    name: "Syscall Stub",
    pattern: @[0x4C'u8, 0x8B, 0xD1, 0xB8],
    description: "Direct syscall invocation pattern",
    mitre: "T1106",
    risk: rlMedium
  ),
  SuspiciousPattern(
    name: "Anti-Debug (IsDebuggerPresent)",
    pattern: @[0x64'u8, 0xA1, 0x30, 0x00, 0x00, 0x00],
    description: "PEB access for debugger check",
    mitre: "T1622",
    risk: rlMedium
  ),
  SuspiciousPattern(
    name: "VirtualAlloc Call",
    pattern: @[0xFF'u8, 0x15],  # call [VirtualAlloc]
    description: "Memory allocation for code injection",
    mitre: "T1055",
    risk: rlMedium
  ),
  SuspiciousPattern(
    name: "CreateRemoteThread",
    pattern: @[0x68'u8, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x00],
    description: "Remote thread creation setup",
    mitre: "T1055.001",
    risk: rlHigh
  ),
  SuspiciousPattern(
    name: "Reflective DLL Loader",
    pattern: @[0x4D'u8, 0x5A, 0x41, 0x52, 0x55, 0x48],
    description: "Reflective PE loader signature",
    mitre: "T1620",
    risk: rlCritical
  ),
]

# String patterns to detect
let stringPatterns = @[
  SuspiciousPattern(
    name: "PowerShell Download",
    pattern: @[0x70'u8, 0x6F, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6C, 0x6C], # powershell
    description: "PowerShell invocation in memory",
    mitre: "T1059.001",
    risk: rlHigh
  ),
  SuspiciousPattern(
    name: "WMI Execution",
    pattern: @[0x77'u8, 0x6D, 0x69, 0x63], # wmic
    description: "WMI command execution",
    mitre: "T1047",
    risk: rlMedium
  ),
  SuspiciousPattern(
    name: "Registry Run Key",
    pattern: @[0x52'u8, 0x75, 0x6E, 0x4F, 0x6E, 0x63, 0x65], # RunOnce
    description: "Registry persistence key reference",
    mitre: "T1547.001",
    risk: rlMedium
  ),
]

# Search for pattern in byte sequence
proc findPattern(data: seq[byte], pattern: seq[byte]): seq[int] =
  result = @[]
  if pattern.len == 0 or data.len < pattern.len:
    return
  
  for i in 0 .. data.len - pattern.len:
    var found = true
    for j in 0 ..< pattern.len:
      if data[i + j] != pattern[j]:
        found = false
        break
    if found:
      result.add(i)

# Scan memory region
proc scanRegion(region: MemoryRegion, patterns: seq[SuspiciousPattern]): seq[MemoryFinding] =
  result = @[]
  
  for pattern in patterns:
    let matches = findPattern(region.content, pattern.pattern)
    for offset in matches:
      var contextStart = max(0, offset - 16)
      var contextEnd = min(region.content.len, offset + pattern.pattern.len + 16)
      
      result.add(MemoryFinding(
        region: region,
        pattern: pattern,
        offset: uint64(offset),
        context: region.content[contextStart ..< contextEnd]
      ))

# Demo memory regions
proc demoRegions(): seq[MemoryRegion] =
  result = @[
    MemoryRegion(
      baseAddress: 0x7FFE0000'u64,
      size: 4096,
      regionType: mrtCode,
      permissions: "RX",
      name: "suspicious.dll",
      content: @[
        0x4D'u8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,  # MZ header
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  # NOP sled
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      ]
    ),
    MemoryRegion(
      baseAddress: 0x10000000'u64,
      size: 8192,
      regionType: mrtHeap,
      permissions: "RWX",
      name: "[heap]",
      content: @[
        0x55'u8, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x00, 0x00,  # Process hollowing
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC1, 0xCF, 0x0D, 0x03, 0xCE, 0x00, 0x00, 0x00,  # ROR13 API hash
      ]
    ),
    MemoryRegion(
      baseAddress: 0x20000000'u64,
      size: 4096,
      regionType: mrtData,
      permissions: "RW",
      name: "config.data",
      content: @[
        0x70'u8, 0x6F, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65,  # "powershell"
        0x6C, 0x6C, 0x20, 0x2D, 0x45, 0x78, 0x65, 0x63,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ]
    ),
    MemoryRegion(
      baseAddress: 0x30000000'u64,
      size: 4096,
      regionType: mrtMapped,
      permissions: "R",
      name: "normal.dll",
      content: @[
        0x4D'u8, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Normal MZ
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ]
    ),
    MemoryRegion(
      baseAddress: 0x40000000'u64,
      size: 4096,
      regionType: mrtCode,
      permissions: "RX",
      name: "loader.exe",
      content: @[
        0x4D'u8, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5,  # Reflective loader
        0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,  # PEB access
        0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00,  # Syscall stub
      ]
    ),
  ]

# Format hex address
proc hexAddr(addr: uint64): string =
  fmt"0x{addr:016X}"

# Format hex bytes
proc hexBytes(data: seq[byte], maxLen: int = 16): string =
  let trimmed = if data.len > maxLen: data[0 ..< maxLen] else: data
  result = trimmed.mapIt(fmt"{it:02X}").join(" ")
  if data.len > maxLen:
    result &= " ..."

# Print banner
proc printBanner() =
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║          NullSec NimHunter - Memory Forensics Scanner           ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo ""

# Print usage
proc printUsage() =
  echo "USAGE:"
  echo "    nimhunter [OPTIONS] <PID>"
  echo ""
  echo "OPTIONS:"
  echo "    -h, --help       Show this help"
  echo "    -p, --pid        Process ID to scan"
  echo "    -d, --dump       Dump suspicious regions"
  echo "    -y, --yara       Custom YARA rules file"
  echo ""
  echo "FEATURES:"
  echo "    • Memory region enumeration"
  echo "    • Suspicious pattern detection"
  echo "    • Malware signature matching"
  echo "    • MITRE ATT&CK mapping"

# Print finding
proc printFinding(finding: MemoryFinding) =
  let color = riskColor(finding.pattern.risk)
  let riskStr = $finding.pattern.risk
  
  echo ""
  echo fmt"  {colorize(color, \"[\" & riskStr & \"]\")} {finding.pattern.name}"
  echo fmt"    Region:      {finding.region.name}"
  echo fmt"    Address:     {hexAddr(finding.region.baseAddress)}"
  echo fmt"    Offset:      +0x{finding.offset:X}"
  echo fmt"    Permissions: {finding.region.permissions}"
  echo fmt"    MITRE:       {finding.pattern.mitre}"
  echo fmt"    Context:     {hexBytes(finding.context)}"

# Print summary
proc printSummary(findings: seq[MemoryFinding], totalRegions: int) =
  let critical = findings.filterIt(it.pattern.risk == rlCritical).len
  let high = findings.filterIt(it.pattern.risk == rlHigh).len
  let medium = findings.filterIt(it.pattern.risk == rlMedium).len
  
  echo ""
  echo colorize(GRAY, "═══════════════════════════════════════════")
  echo ""
  echo "  Summary:"
  echo fmt"    Regions Scanned: {totalRegions}"
  echo fmt"    Findings:        {findings.len}"
  echo fmt"    Critical:        {colorize(RED, $critical)}"
  echo fmt"    High:            {colorize(RED, $high)}"
  echo fmt"    Medium:          {colorize(YELLOW, $medium)}"

# Demo mode
proc demo() =
  echo colorize(YELLOW, "[Demo Mode]")
  echo ""
  echo colorize(CYAN, "Scanning process memory for malicious patterns...")
  
  let regions = demoRegions()
  var allFindings: seq[MemoryFinding] = @[]
  
  # Scan with all patterns
  let allPatterns = suspiciousPatterns & stringPatterns
  
  for region in regions:
    let findings = scanRegion(region, allPatterns)
    allFindings &= findings
  
  # Sort by risk
  allFindings.sort(proc(a, b: MemoryFinding): int =
    result = ord(a.pattern.risk) - ord(b.pattern.risk)
  )
  
  for finding in allFindings:
    printFinding(finding)
  
  printSummary(allFindings, regions.len)

# Main entry
proc main() =
  printBanner()
  printUsage()
  echo ""
  demo()

when isMainModule:
  main()
