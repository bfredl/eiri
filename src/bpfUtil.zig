const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const fd_t = linux.fd_t;
const mem = std.mem;
const errno = linux.getErrno;

// TODO: all of this should be extended and then upstreamed to zig stdlib

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
