const std = @import("std");
const bpfUtil = @import("./bpfUtil.zig");
const Codegen = @import("./Codegen.zig");
const ElfSymbols = @import("./ElfSymbols.zig");
const FLIR = @import("./FLIR.zig");
const RingBuf = @import("./RingBuf.zig");
const linux = std.os.linux;
const BPF = linux.BPF;
const PERF = linux.PERF;
const Insn = BPF.Insn;
const io = std.io;
const mem = std.mem;
const fd_t = linux.fd_t;
const errno = linux.getErrno;
const print = std.debug.print;
// const libbpf = @import("bpf");
// const PerfBuffer = libbpf.PerfBuffer;

pub fn perf_attach_bpf(target: fd_t, prog: fd_t) !void {
    if (linux.ioctl(target, PERF.EVENT_IOC.SET_BPF, @intCast(u64, prog)) < 0) {
        return error.Failed_IOC_SET_BPF;
    }
    if (linux.ioctl(target, PERF.EVENT_IOC.ENABLE, 0) < 0) {
        return error.Failed_IOC_ENABLE;
    }
}

pub fn perf_open_uprobe(uprobe_type: u32, uprobe_path: [:0]const u8, uprobe_offset: u64) !fd_t {
    // TODO: .size should be the default (stage2 bug)
    var attr = linux.perf_event_attr{ .size = @sizeOf(linux.perf_event_attr) };

    // TODO: use /sys/devices/system/cpu/online
    // but not needed for uprobe/kprobe???

    // the type value is dynamic and might be outside the defined values of
    // PERF.TYPE. praxis or zig std correctness issue
    attr.type = @intToEnum(PERF.TYPE, uprobe_type);
    attr.sample_period_or_freq = 1;
    attr.wakeup_events_or_watermark = 1;
    attr.config1 = @ptrToInt(uprobe_path.ptr);
    attr.config2 = uprobe_offset;

    const rc = linux.perf_event_open(&attr, -1, 0, -1, 0);
    return switch (errno(rc)) {
        .SUCCESS => @intCast(fd_t, rc),
        .ACCES => error.UnsafeProgram,
        .FAULT => error.BPFProgramFault,
        .INVAL => error.InvalidArgument,
        .PERM => error.AccessDenied,
        else => |err| std.os.unexpectedErrno(err),
    };
}

pub fn getUprobeType() !u32 {
    const fil = try std.fs.openFileAbsolute("/sys/bus/event_source/devices/uprobe/type", .{});
    defer fil.close();

    const reader = fil.reader();
    var buf = [1]u8{0} ** 32;
    const line = (try reader.readUntilDelimiterOrEof(&buf, '\n')) orelse return error.FEEL;
    return std.fmt.parseInt(u32, line, 10);
}

pub fn test_stack(allocator: std.mem.Allocator) !void {
    var c = try Codegen.init(allocator);
    var ir = try FLIR.init(4, allocator);

    const start = try ir.addNode();
    // const arg0 = try ir.ctx_arg();
    const arg0 = try ir.const_int(start, 0xFFF);
    const callptr = try ir.alloc(start);
    const const_0 = try ir.const_int(start, 0);
    const BPF_F_USER_STACK = 0x0100;
    const flags = try ir.const_int(start, BPF_F_USER_STACK);
    const size = try ir.const_int(start, 8);
    var res = try ir.call4(start, .get_stack, arg0, callptr, size, flags);
    _ = res;
    try ir.ret(start, const_0);
    try ir.test_analysis();
    ir.debug_print();
    _ = try Codegen.codegen(&ir, &c);
    print("\n", .{});
    c.dump();
}

pub fn test_map(c: *Codegen, allocator: std.mem.Allocator, map: fd_t) !void {
    var ir = try FLIR.init(4, allocator);

    const start = try ir.addNode();
    const keyvar = try ir.alloc(start);
    const const_0 = try ir.const_int(start, 0);
    _ = try ir.store(start, keyvar, const_0);
    const m = try ir.load_map_fd(start, @intCast(u32, map));
    var res = try ir.call2(start, .map_lookup_elem, m, keyvar);
    const const_1 = try ir.const_int(start, 1);
    _ = try ir.icmp(start, .jeq, res, const_0);
    const doit = try ir.addNode();
    _ = try ir.xadd(doit, res, const_1);
    const end = try ir.addNode();
    try ir.ret(end, const_0);
    ir.n.items[start].s[0] = doit;
    ir.n.items[start].s[1] = end;
    ir.n.items[doit].s[0] = end;

    ir.debug_print();
    try ir.test_analysis();
    ir.debug_print();
    const pos = try Codegen.codegen(&ir, c);
    _ = pos;
}

pub fn test_ringbuf(c: *Codegen, allocator: std.mem.Allocator, ringbuf: fd_t) !void {
    var ir = try FLIR.init(4, allocator);

    const start = try ir.addNode();
    const const_0 = try ir.const_int(start, 0);
    const const_8 = try ir.const_int(start, 8);
    const m = try ir.load_map_fd(start, @intCast(u32, ringbuf));
    var res = try ir.call3(start, .ringbuf_reserve, m, const_8, const_0);
    // TODO: ad an else which increments "discarded" counter like test_ringbuf.c
    _ = try ir.icmp(start, .jeq, res, const_0);
    const doit = try ir.addNode();
    const const_57 = try ir.const_int(doit, 57);
    _ = try ir.store(doit, res, const_57);
    _ = try ir.call2(doit, .ringbuf_submit, res, const_0);

    const end = try ir.addNode();
    try ir.ret(end, const_0);
    ir.n.items[start].s[0] = doit;
    ir.n.items[start].s[1] = end;
    ir.n.items[doit].s[0] = end;

    ir.debug_print();
    try ir.test_analysis();
    ir.debug_print();
    const pos = try Codegen.codegen(&ir, c);
    _ = pos;
}

pub fn test_get_usdt(sdts: []ElfSymbols.Stapsdt, sdtname: []const u8) !ElfSymbols.Stapsdt {
    for (sdts) |i| {
        print("IYTEM: {} {s} {s} {s}\n", .{ i.h, i.provider, i.name, i.argdesc });
        if (mem.eql(u8, i.name, sdtname)) {
            return i;
        }
    }
    return error.ProbeNotFound;
}

pub fn prog_load_verbose(prog_type: BPF.ProgType, c: []BPF.Insn) !fd_t {
    var loggen = [1]u8{0} ** 512;
    var log = BPF.Log{ .level = 4, .buf = &loggen };
    return BPF.prog_load(prog_type, c, &log, "MIT", 0) catch |err| {
        print("ERROR {s}\n", .{mem.sliceTo(&loggen, 0)});
        return err;
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const buffer_size: usize = 1024 * 4;
    const ring_map_fd = if (std.os.argv.len > 1) try BPF.map_create(.ringbuf, 0, 0, buffer_size) else 57;
    var ringbuf = try RingBuf.init(allocator, ring_map_fd, buffer_size);
    print("MAPPA: {} {}\n", .{ ring_map_fd, ringbuf.read_event() });

    var c = try Codegen.init(allocator);

    // try test_stack(allocator);

    // dummy value for dry run
    const map = if (std.os.argv.len > 1) try BPF.map_create(.array, 4, 8, 1) else 23;

    // try test_map(&c, allocator, map);

    try test_ringbuf(&c, allocator, map);
    // c.dump();

    if (std.os.argv.len <= 1) return;

    const prog = try prog_load_verbose(.kprobe, c.prog());

    const fname = mem.span(std.os.argv[1]);
    const sdtname = mem.span(std.os.argv[2]);
    const elf = try ElfSymbols.init(try std.fs.cwd().openFile(fname, .{}));
    defer elf.deinit();
    const sdts = try elf.get_sdts(allocator);
    defer sdts.deinit();

    const sdt = try test_get_usdt(sdts.items, sdtname);

    const uprobe_type = try getUprobeType();
    const probe_fd = try perf_open_uprobe(uprobe_type, fname, sdt.h.pc);

    // TODO: would be nice if this works so we don't need ioctls..
    // _ = try bpfUtil.prog_attach_perf(probe_fd, prog);
    try perf_attach_bpf(probe_fd, prog);

    var lastval: u64 = @truncate(u64, -1);
    while (true) {
        const key: u32 = 0;
        var value: u64 = undefined;
        try BPF.map_lookup_elem(map, mem.asBytes(&key), mem.asBytes(&value));
        if (value < lastval or value > lastval + 1000) {
            print("VALUE: {}. That's NUMBERWANG!\n", .{value});
            lastval = value;
        }
        std.time.sleep(1e9);
    }

    // doesn't work on kprobe programs (more context needed?)
    // const retval = try bpfUtil.prog_test_run(prog);
    // print("RETURNERA: {}\n", .{retval});
    defer std.os.close(prog);
}
