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
// const libbpf = @import("bpf");
// const PerfBuffer = libbpf.PerfBuffer;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const for_real = true; // MEN JAG VILL VETA HUR

    const irfname = mem.span(std.os.argv[1]);
    const fil = try std.fs.cwd().openFile(irfname, .{});
    const input = try ElfSymbols.bytemap_ro(fil);
    var parser = Parser.init(input, allocator);
    // try parser.fd_objs.put("count", map_count);
    parser.parse(for_real) catch |e| {
        print("G00f at {} of {}\n", .{ parser.pos, input.len });
        return e;
    };

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
