# PWN Handbook for CTF players

Technical reference notes and structured breakdowns covering binary exploitation fundamentals, stack and format string mechanics, heap allocators, and `glibc` `FILE`-stream (`_IO_FILE`) internals.

## Overview

This document compiles practical notes, memory layouts, structure offsets, and step-by-step analyses collected during CTF challenge research and local laboratory testing in `glibc` environments. It is structured as a reference handbook for studying allocator behavior and stream internals across different `glibc` versions.

## Contents

- **Basics & Stack**: Foundational exploitation concepts, calling conventions, and stack frame mechanics.
- **Format String**: Behavior and exploitation primitives of format string vulnerabilities.
- **Heap Exploitation**: Allocator structures, chunk lifecycles, and techniques including House of Orange, House of Spirit, Unsorted Bin, Large Bin, and Tcache attacks (including Tcache Stashing Unlink).
- **FSOP (`_IO_FILE` & Stream Internals)**:
  - `_IO_FILE` and `_IO_FILE_plus` structure layouts and `vtable` validation
  - `_IO_str_jumps` and related stream dispatch paths
  - Manipulations with `stdin` (`_IO_2_1_stdin_`) buffer pointers (`buf_base`, `buf_end`) for arbitrary write primitives
  - **House of Apple 2**: `_IO_wide_data` and `_wide_vtable` (`_IO_wfile_jumps`, `_IO_wdoallocbuf`) mechanics
  - **House of Emma**: `_IO_cookie_file`, `_IO_cookie_jumps`, and `PTR_MANGLE` / `PTR_DEMANGLE` with `POINTER_GUARD` (`\$fs_base + 0x30`)
- **Bonus**: self research and self notes for a lot of topics including specific contexts
- **Non-Standart Archs and another**: my experience at arm32, qemu-escape, custom kernels etc.  

## Scope and Conventions

- **Target Environment**: Linux (`x86_64`) and `glibc` internals across pre- and post-`2.30` / `2.43` behavior.
- **Methodology**: Empirical verification using GDB (`gef` / `pwndbg` / `peda`), `pwntools`, and local proof-of-concept test harnesses.
- **Formatting**: Standard Markdown with fenced code blocks for C snippets, disassembly, and memory dumps.
