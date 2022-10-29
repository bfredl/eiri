Eiri
=======

Minimal self-contained eBPF/uprobe based tracer.

Work in progress. Currently can attach to USDT probes in ELF files and run
simple eBPF programs defined in a custom IR format. ringbuf output gets printed as raw bytes to stderr.

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

attach $neovim flushy $main
```
