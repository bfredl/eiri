const std = @import("std");
const bpfUtil = @import("./bpfUtil.zig");
const Codegen = @import("./Codegen.zig");
const ElfSymbols = @import("./ElfSymbols.zig");
const FLIR = @import("./FLIR.zig");
const RingBuf = @import("./RingBuf.zig");
const Parser = @import("./Parser.zig");
const os = std.os;
const BPF = os.linux.BPF;
const Insn = BPF.Insn;
const io = std.io;
const mem = std.mem;
const fd_t = os.linux.fd_t;
const errno = os.linux.getErrno;
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
        \\    s: print used symbol addresses
        \\
    , .{});
}

var did_int = false;
fn on_sigint(sig: i32, info: *const os.siginfo_t, ctx_ptr: ?*const anyopaque) callconv(.C) void {
    _ = sig;
    _ = info;
    _ = ctx_ptr;
    did_int = true;
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

    const count_map = try parser.get_obj("count", .map);
    var ncount: usize = 0;
    if (count_map) |map| {
        if (map.key_size != 4 or map.val_size % 8 != 0) {
            return error.whatthef;
        }
        ncount = map.val_size / 8;
    }

    const hash_map = try parser.get_obj("hashmap", .map);
    if (hash_map) |map| {
        if (map.key_size != 4 or map.val_size != 8) {
            return error.whatthef;
        }
    }

    const stack_map = try parser.get_obj("stackmap", .map);
    if (stack_map) |map| {
        if (map.key_size != 4 or map.val_size > 1024) {
            return error.whatthef;
        }
    }

    var sa = os.Sigaction{
        .handler = .{ .sigaction = on_sigint },
        .mask = os.empty_sigset,
        .flags = os.SA.SIGINFO,
    };
    try os.sigaction(os.SIG.INT, &sa, null);

    var lastval: []u64 = try allocator.alloc(u64, ncount);
    var countval: []u64 = try allocator.alloc(u64, ncount);
    const asBytes = mem.asBytes;
    while (!did_int) {
        std.time.sleep(1e9);
        if (count_map) |map| {
            const key: u32 = 0;
            try BPF.map_lookup_elem(map.fd, asBytes(&key), mem.sliceAsBytes(countval));
            if (!mem.eql(u64, lastval, countval)) {
                print("VALUE: {}. That's NUMBERWANG!\n", .{countval[0]});
                mem.copy(u64, lastval, countval);
                for (countval[1..]) |val, i| {
                    if (map.val_size >= 16) {
                        print("EXTRA VALUE {}: {}\n", .{ i + 1, val });
                    }
                }
            }
        }
        if (ringbuf) |*rb| {
            while (rb.peek_event()) |ev| {
                did_read = true;
                print("VERY EVENT: {}\n", .{ev});
                rb.consume_event(ev);
            }
        }
    }
    print("interrupted.\n", .{});

    if (hash_map) |hash| {
        var info: ?std.debug.ModuleDebugInfo = null;

        const elf = try parser.get_obj("neovim", .elf);
        if (elf) |e| {
            const filen = try std.fs.cwd().openFile(e.fname, .{});
            // TODO: cringe, reuse existing mmapping of elf.syms
            info = try std.debug.readElfDebugInfo(allocator, filen);
            info.?.base_address = 0; // TODO: CRINGE
            print("INFON: {}\n", .{info.?.dwarf.func_list.items[0]});
        }

        var key: u32 = 0;
        var next_key: u32 = 0;
        print("hashy: \n", .{});

        const Pair = struct {
            key: u32,
            value: u64,
            const Self = @This();
            fn compare(ctx: void, lhs: Self, rhs: Self) bool {
                _ = ctx;
                return lhs.value < rhs.value;
            }
        };
        var kv_pairs = try std.ArrayList(Pair).initCapacity(allocator, 1024);
        defer kv_pairs.deinit();
        var summa: u64 = 0;

        while (try BPF.map_get_next_key(hash.fd, asBytes(&key), asBytes(&next_key))) {
            key = next_key;
            var value: u64 = 0;
            try BPF.map_lookup_elem(hash.fd, asBytes(&key), asBytes(&value));
            try kv_pairs.append(.{ .key = key, .value = value });
            summa += value;
        }

        std.sort.sort(Pair, kv_pairs.items, {}, Pair.compare);
        var bottensumma: u64 = 0;

        for (kv_pairs.items) |iytem| {
            bottensumma += iytem.value;
            if (bottensumma * 10 < summa) continue;
            print("{}:", .{iytem.value});
            if (stack_map) |stack| {
                var trace: [128]u64 = [1]u64{0xDEADBEEFDEADF00D} ** 128;
                BPF.map_lookup_elem(stack.fd, asBytes(&iytem.key), asBytes(&trace)) catch |e| {
                    print("\nSTÄMNINGSJAZZ: {}\n", .{e});
                    if (e == error.NotFound) continue;
                    return e;
                };
                if (info) |*i| {
                    print("\n", .{});
                    for (trace[0..5]) |t| {
                        const address = adj(t);
                        const sym = try i.getSymbolAtAddress(allocator, address);
                        defer sym.deinit(allocator);

                        print("{s}: 0x{x}", .{ sym.symbol_name, address });
                        if (sym.line_info) |*li| {
                            print(" at {s}:{d}:{d}\n", .{ li.file_name, li.line, li.column });
                        } else {
                            print("\n", .{});
                        }
                    }
                } else {
                    print("0x{x} 0x{x} 0x{x}\n", .{ adj(trace[0]), adj(trace[1]), adj(trace[2]) });
                }
            }
        }

        print("\n summa: {}\n", .{summa});
        if (ncount > 0) {
            print("compare: {}\n", .{countval[0]});
        }
    }
    print("FIN.\n", .{});
}

fn adj(val: u64) u64 {
    // TODO: we can figure this out dynamically by taking the $rip at some
    // know function. then also ASLR of the main binary will be supported.
    const off: u64 = 0x555555554000;
    return if (val > off) val - off else val;
}
