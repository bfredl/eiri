Eiri
=======

Minimal self-contained eBPF/kprobe based tracer.

Work in progress. Currently can attach to kprobes as well as USDT probes in ELF files and run
simple eBPF programs defined in a custom IR format.

Very simple output is supported. in form of a single count (stored as a bpf array map) or dumping byte values in a bpf ringbuf map


Examples
-----

use array map as simple counter:
```
map $count array 4 8 1

func $main MIT
  %key = alloc
  store [%key] 0
  %map = map $count
  %aa = call map_lookup_elem %map %key
  eq %aa 0 :exit
:doit
  xadd [%aa] 1
:exit
  ret 0
end

attach $main kprobe __x64_sys_write
```

dump userland stack into ringbuf:
```
map $ringbuf ringbuf 0 0 4096

func $main GPL
  %ctx = arg
  %map = map $ringbuf
  %buf = call ringbuf_reserve %map 16 0
  eq %buf 0 :exit
:doit
  %res = call get_stack %ctx %buf 16 256
  %status = call ringbuf_submit %buf 0
:exit
  ret 0
end

elf $neovim /home/bfredl/dev/neovim/build/bin/nvim

attach usdt $neovim xfree
```

Disassembly
---
Included is a disassembler (being gradually implemented along with codegen..). To display the analyzed IR and generated BPF code use the debug flags:

```
./zig-out/eiri -tad stack.ir
```

Example assembler output:

```
  0: bf 6 1  +0   +0 MOV64 r6, r1
  1: 18 7 1  +0  +39 LD r7, map_fd 57
  2: 00 0 0  +0   +0
  3: bf 1 7  +0   +0 MOV64 r1, r7
  4: b7 2 0  +0  +10 MOV64 r2, 16
  5: b7 3 0  +0   +0 MOV64 r3, 0
  6: 85 0 0  +0  +83 CALL $ringbuf_reserve
  7: bf 7 0  +0   +0 MOV64 r7, r0
  8: 15 7 0  +8   +0 JEQ r7, 0 => 17
  9: bf 1 6  +0   +0 MOV64 r1, r6
 10: bf 2 7  +0   +0 MOV64 r2, r7
 11: b7 3 0  +0  +10 MOV64 r3, 16
 12: b7 4 0  +0 +100 MOV64 r4, 256
 13: 85 0 0  +0  +43 CALL $get_stack
 14: bf 1 7  +0   +0 MOV64 r1, r7
 15: b7 2 0  +0   +0 MOV64 r2, 0
 16: 85 0 0  +0  +84 CALL $ringbuf_submit
 17: b7 0 0  +0   +0 MOV64 r0, 0
 18: 95 0 0  +0   +0 EXIT

```
