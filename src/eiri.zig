const std = @import("std");
const bpfUtil = @import("./bpfUtil.zig");
const ElfSymbols = @import("./ElfSymbols.zig");
const linux = std.os.linux;
const BPF = linux.BPF;
const PERF = linux.PERF;
const Insn = BPF.Insn;
const io = std.io;
const mem = std.mem;
const fd_t = linux.fd_t;
const errno = linux.getErrno;
const p = std.debug.print;

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

pub fn main() !void {
    const arg = mem.span(std.os.argv[1]);
    const elf = try ElfSymbols.init(try std.fs.cwd().openFile(arg, .{}));
    const sdt = elf.get_sdts().?;
    _ = sdt;
    defer elf.deinit();

    const map = try BPF.map_create(.array, 4, 8, 1);
    const perf_map = try BPF.map_create(.perf, 4, 4, 2);

    const I = Insn;
    const uprobe_prog = [_]Insn{
        I.mov(.r6, .r1), // r6 = ctx
        I.mov(.r0, 0),
        I.stx(.word, .r10, -4, .r0), // word [r10-4] = 0
        I.mov(.r2, .r10),
        I.add(.r2, -4), //              r2 = r10-4
        I.ld_map_fd1(.r1, map), //      r1 = load_map(map)
        I.ld_map_fd2(map),
        I.call(.map_lookup_elem), //    r0 = lookup(r1, r2)
        I.jeq(.r0, 0, 13), //            if (r0 != 0) {
        I.mov(.r1, 1),
        // TODO: UGLY, add Inst.atomic_op to stdlib BPF module
        I.xadd(.r0, .r1), //              qword [r0] += 0 (atomic)
        I.ldx(.word, .r3, .r0, 0), // r2 = [r0]
        I.jle(.r2, 100000, 9),
        I.mov(.r1, .r6), // r1 = ctx
        I.ld_map_fd1(.r2, perf_map), //      r2 = load_map(perf_map)
        I.ld_map_fd2(perf_map),
        I.stx(.dword, .r10, -8, .r3), // word [r10-8] = r3
        I.mov(.r3, 0), // r3 = 0 (flags)
        I.mov(.r4, .r10),
        I.add(.r4, -8), //              r4 = r10-8
        I.mov(.r5, 8),
        I.call(.perf_event_output), //    r0 = lookup(r1, r2)
        //                              }
        //                              }
        I.exit(),
    };
    var loggen = [1]u8{0} ** 512;
    var log = BPF.Log{ .level = 4, .buf = &loggen };
    const prog = BPF.prog_load(.kprobe, &uprobe_prog, &log, "MIT", 0) catch |err| {
        p("ERROR {s}\n", .{mem.sliceTo(&loggen, 0)});
        return err;
    };

    const uprobe_type = try getUprobeType();
    const probe_fd = try perf_open_uprobe(uprobe_type, arg, sdt.h.pc);

    // TODO: would be nice if this works so we don't need ioctls..
    // _ = try bpfUtil.prog_attach_perf(probe_fd, prog);
    try perf_attach_bpf(probe_fd, prog);

    var lastval: u64 = @truncate(u64, -1);
    while (true) {
        const key: u32 = 0;
        var value: u64 = undefined;
        try BPF.map_lookup_elem(map, mem.asBytes(&key), mem.asBytes(&value));
        if (value < lastval or value > lastval + 1000) {
            p("VALUE: {}. That's NUMBERWANG!\n", .{value});
            lastval = value;
        }
        std.time.sleep(1e9);
    }

    // doesn't work on kprobe programs (more context needed?)
    // const retval = try bpfUtil.prog_test_run(prog);
    // p("RETURNERA: {}\n", .{retval});
    defer std.os.close(prog);
}
