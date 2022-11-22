const std = @import("std");
const bpfUtil = @import("./bpfUtil.zig");
const Codegen = @import("./Codegen.zig");
const ElfSymbols = @import("./ElfSymbols.zig");
const FLIR = @import("./FLIR.zig");
const RingBuf = @import("./RingBuf.zig");
const Parser = @import("./Parser.zig");
const linux = std.os.linux;
const BPF = linux.BPF;
const Insn = BPF.Insn;
const io = std.io;
const mem = std.mem;
const fd_t = linux.fd_t;
const errno = linux.getErrno;
const print = std.debug.print;

pub var options = struct {
    dbg_raw_ir: bool = false,
    dbg_analysed_ir: bool = false,
    dbg_disasm: bool = false,
    dbg_disasm_ir: bool = false,
    dbg_syms: bool = false,
    sys: bool = true,
}{};

pub fn usage() void {
    print(
        \\USAGE: eiri [-tiadD] program.ir
        \\
        \\debug flags:
        \\    t: test run, disable all BPF syscalls
        \\    i: print input IR
        \\    a: print analyzed IR
        \\    d: print BPF disassembly
        \\    D: print BPF disassembly per IR node
        \\
    , .{});
}

pub fn main() !void {
    const mode = @import("builtin").mode;
    var gpa = if (mode == .Debug)
        std.heap.GeneralPurposeAllocator(.{}){}
    else
        std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = gpa.allocator();

    const argv = std.os.argv;
    if (argv.len < 2) return usage();
    const firstarg = mem.span(argv[1]);
    var filearg = firstarg;
    if (firstarg[0] == '-') {
        if (argv.len < 3) return usage();
        filearg = mem.span(argv[2]);
        for (firstarg[1..]) |a| {
            switch (a) {
                'i' => options.dbg_raw_ir = true,
                'a' => options.dbg_analysed_ir = true,
                'd' => options.dbg_disasm = true,
                'D' => options.dbg_disasm_ir = true,
                's' => options.dbg_syms = true,
                't' => options.sys = false,
                else => return usage(),
            }
        }
    }

    const fil = try std.fs.cwd().openFile(filearg, .{});
    const input = try ElfSymbols.bytemap_ro(fil);
    var parser = Parser.init(input, allocator);
    // try parser.fd_objs.put("count", map_count);
    parser.parse() catch |e| {
        print("error at byte {} of {}\n", .{ parser.pos, input.len });
        return e;
    };

    if (!options.sys) return;

    var ringbuf = if (try parser.get_obj("ringbuf", .map)) |map|
        try RingBuf.init(allocator, map.fd, map.entries)
    else
        null;
    var did_read = false;

    var count_map = try parser.get_obj("count", .map);
    if (count_map) |map| {
        if (map.key_size != 4 or map.val_size != 8) {
            return error.whatthef;
        }
    }

    var lastval: u64 = @truncate(u64, -1);
    while (true) {
        if (count_map) |map| {
            const key: u32 = 0;
            var value: u64 = undefined;
            try BPF.map_lookup_elem(map.fd, mem.asBytes(&key), mem.asBytes(&value));
            if (value < lastval or value > lastval + 1) {
                print("VALUE: {}. That's NUMBERWANG!\n", .{value});
                lastval = value;
            }
        }
        std.time.sleep(1e9);
        if (ringbuf) |*rb| {
            while (rb.peek_event()) |ev| {
                did_read = true;
                print("VERY EVENT: {}\n", .{ev});
                rb.consume_event(ev);
            }
        }
    }

    // doesn't work on kprobe programs (more context needed?)
    // const retval = try bpfUtil.prog_test_run(prog);
    // print("RETURNERA: {}\n", .{retval});
}
