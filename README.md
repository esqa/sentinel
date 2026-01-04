# Sentinel

A SIMD-accelerated byte pattern scanner for Windows PE modules.

## Overview

Sentinel scans the `.text` section of loaded Windows modules to find byte sequences matching a given pattern. It uses SSE2 intrinsics to compare 16 bytes at a time, with a lead-byte optimization to quickly skip non-matching regions.

## Features

- SIMD-accelerated comparison using SSE2
- Scans only the `.text` section of PE modules

## Requirements

Requires Clang due to the use of variable length arrays (VLAs).

## Usage

```cpp
#include "sentinel.h"

void* module = GetModuleHandle("example.dll");

sentinel::sequence seq[256];
int length = sentinel::parse_pattern("48 8B ?? 48 85 C0 74", seq);

void* address = sentinel::find_signature(module, seq, length);
```

## Pattern Format

- Hex bytes separated by spaces: `48 8B 05`
- Wildcards: `?` or `??` match any byte
- Example: `E8 ?? ?? ?? ?? 48 8B D8`
