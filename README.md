Eiri
=======

Minimal self-contained eBPF/kprobe based tracer.

Work in progress. Currently can attach to kprobes as well as USDT probes in ELF files and run
simple eBPF programs defined in a custom IR format. ringbuf output gets printed as raw bytes to stderr.

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
