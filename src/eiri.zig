const std = @import("std");
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

pub fn prog_test_run(
    prog: fd_t,
) !u32 {
    var attr = BPF.Attr{
        .test_run = mem.zeroes(BPF.TestRunAttr),
    };

    attr.test_run.prog_fd = prog;
    attr.test_run.repeat = 1;

    var dummy_data = [1]u8{0} ** 32;
    attr.test_run.data_size_in = dummy_data.len;
    attr.test_run.data_in = @ptrToInt(&dummy_data);

    const rc = linux.bpf(.prog_test_run, &attr, @sizeOf(BPF.TestRunAttr));
    // TODO: check the docs for actually expected errors
    return switch (errno(rc)) {
        .SUCCESS => attr.test_run.retval,
        .ACCES => error.UnsafeProgram,
        .FAULT => error.BPFProgramFault,
        .INVAL => error.InvalidArgument,
        .PERM => error.AccessDenied,
        else => |err| std.os.unexpectedErrno(err),
    };
}

pub fn prog_attach_perf(target: fd_t, prog: fd_t) !u32 {
    var attr = BPF.Attr{
        .prog_attach = mem.zeroes(BPF.ProgAttachAttr),
    };

    const BPF_PERF_EVENT = 41;

    attr.prog_attach.target_fd = target;
    attr.prog_attach.attach_bpf_fd = prog;
    attr.prog_attach.attach_type = BPF_PERF_EVENT;

    const rc = linux.bpf(.prog_attach, &attr, @sizeOf(BPF.ProgAttachAttr));
    // TODO: check the docs for actually expected errors
    return switch (errno(rc)) {
        .SUCCESS => attr.test_run.retval,
        .ACCES => error.UnsafeProgram,
        .FAULT => error.BPFProgramFault,
        .INVAL => error.InvalidArgument,
        .PERM => error.AccessDenied,
        else => |err| std.os.unexpectedErrno(err),
    };
}

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
    p("MAPPA {}\n", .{map});

    const I = Insn;
    const uprobe_prog = [_]Insn{
        I.mov(.r0, 0),
        // I.stx(.word, .r10, -4, .r0), // word [r10-4] = 0
        // I.mov(.r2, .r10),
        // I.add(.r2, -4), //              r2 = r10-4
        I.ld_map_fd1(.r1, map), //      r1 = load_map(map)
        // I.call(.map_lookup_elem), //    r0 = lookup(r1, r2)
        // I.jeq(.r0, 0, 2), //            if (r0 != 0) {
        // I.mov(.r1, 1),
        // TODO: UGLY, add Inst.atomic_op to stdlib BPF module
        // I.xadd(.r0, .r1), //              dword [r0] += 0 (atomic)
        //                              }
        I.exit(),
    };
    var loggen = [1]u8{0} ** 512;
    var log = BPF.Log{ .level = 4, .buf = &loggen };
    const prog = BPF.prog_load(.kprobe, &uprobe_prog, &log, "MIT", 0) catch |err| {
        p("ERROR {s}\n", .{mem.sliceTo(&loggen, 0)});
        return err;
    };

    var uprobe_type = try getUprobeType();
    p("proben: {}\n", .{uprobe_type});
    const probe_fd = try perf_open_uprobe(uprobe_type, arg, sdt.h.pc);

    p("probe_fd: {}\n", .{probe_fd});
    // TODO: would be nice if this works so we don't need ioctls..
    // _ = try prog_attach_perf(probe_fd, prog);
    try perf_attach_bpf(probe_fd, prog);

    // doesn't work on kprobe programs (more context needed?)
    // const retval = try prog_test_run(prog);
    // p("RETURNERA: {}\n", .{retval});
    defer std.os.close(prog);
}
