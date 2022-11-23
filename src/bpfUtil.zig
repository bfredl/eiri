const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const fd_t = linux.fd_t;
const mem = std.mem;
const errno = linux.getErrno;
const PERF = linux.PERF;
const print = std.debug.print;

// TODO: all of this should be extended and then upstreamed to zig stdlib

pub fn prog_test_run(
    prog: fd_t,
) !u32 {
    var attr = Attr{
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
    var attr = Attr{
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

pub fn perf_open_probe(probe_type: u32, config1: u64, config2: u64) !fd_t {
    var attr = linux.perf_event_attr{};

    // TODO: use /sys/devices/system/cpu/online
    // but not needed for uprobe/kprobe???

    // the type value is dynamic and might be outside the defined values of
    // PERF.TYPE. praxis or zig std correctness issue
    attr.type = @intToEnum(PERF.TYPE, probe_type);
    attr.sample_period_or_freq = 1;
    attr.wakeup_events_or_watermark = 1;

    attr.config1 = config1;
    attr.config2 = config2;

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

// makes a null-terminated copy of config1, maximum size: 511 bytes (+ added nul byte)
pub fn perf_open_probe_cstr(uprobe_type: u32, config1: []const u8, config2: u64) !fd_t {
    var config1_buf: [512]u8 = undefined;
    if (config1.len > 511) return error.InvalidProgram;
    mem.copy(u8, &config1_buf, config1);
    config1_buf[config1.len] = 0;

    return perf_open_probe(uprobe_type, @ptrToInt(&config1_buf), config2);
}

pub fn getProbeTypeFromPath(path: []const u8) !u32 {
    const fil = try std.fs.openFileAbsolute(path, .{});
    defer fil.close();

    const reader = fil.reader();
    var buf = [1]u8{0} ** 32;
    const line = (try reader.readUntilDelimiterOrEof(&buf, '\n')) orelse return error.FEEL;
    return std.fmt.parseInt(u32, line, 10);
}

pub fn getKprobeType() !u32 {
    return getProbeTypeFromPath("/sys/bus/event_source/devices/kprobe/type");
}

pub fn getUprobeType() !u32 {
    return getProbeTypeFromPath("/sys/bus/event_source/devices/uprobe/type");
}

pub const pt_regs_amd64 = enum(u8) {
    r15,
    r14,
    r13,
    r12,
    rbp,
    rbx,
    r11,
    r10,
    r9,
    r8,
    rax,
    rcx,
    rdx,
    rsi,
    rdi,
    // On syscall entry, this is syscall#. On CPU exception, this is error code.
    // On hw interrupt, it's IRQ number:
    orig_ax,
    ip,
    cs,
    flags,
    rsp,
    ss,
};

pub fn pt_off(reg: pt_regs_amd64) u16 {
    // TODO: also for AARCH64 etc, of c
    return @enumToInt(reg) * 8;
}

pub fn prog_load_verbose(prog_type: BPF.ProgType, c: []BPF.Insn, license: []const u8) !fd_t {
    var loggen = [1]u8{0} ** 512;
    var log = BPF.Log{ .level = 4, .buf = &loggen };
    var license_buf: [32]u8 = undefined;
    if (license.len > 31) return error.InvalidProgram;
    mem.copy(u8, &license_buf, license);
    license_buf[license.len] = 0;
    return BPF.prog_load(prog_type, c, &log, &license_buf, 0) catch |err| {
        print("ERROR {s}\n", .{mem.sliceTo(&loggen, 0)});
        return err;
    };
}

const Attr = BPF.Attr;
const MapElemAttr = BPF.MapElemAttr;
const unexpectedErrno = std.os.unexpectedErrno;

pub fn map_get_next_key(fd: fd_t, key: []const u8, next_key: []u8) !bool {
    var attr = Attr{
        .map_elem = std.mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @ptrToInt(key.ptr);
    attr.map_elem.result.next_key = @ptrToInt(next_key.ptr);

    const rc = linux.bpf(.map_get_next_key, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        .SUCCESS => return true,
        .BADF => return error.BadFd,
        .FAULT => unreachable,
        .INVAL => return error.FieldInAttrNeedsZeroing,
        .NOENT => return false,
        .PERM => return error.AccessDenied,
        else => |err| return unexpectedErrno(err),
    }
}
