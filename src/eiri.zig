const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const Insn = BPF.Insn;

const fd_t = linux.fd_t;
const errno = linux.getErrno;

pub fn prog_test_run(
    prog: fd_t,
) !u32 {
    var attr = BPF.Attr{
        .test_run = std.mem.zeroes(BPF.TestRunAttr),
    };

    attr.test_run.prog_fd = prog;

    const rc = linux.bpf(.prog_load, &attr, @sizeOf(BPF.TestRunAttr));
    return switch (errno(rc)) {
        .SUCCESS => attr.test_run.retval,
        .ACCES => error.UnsafeProgram,
        .FAULT => error.BPFProgramFault,
        .INVAL => error.InvalidProgram,
        .PERM => error.AccessDenied,
        else => |err| std.os.unexpectedErrno(err),
    };
}
pub fn main() !void {
    const good_prog = [_]Insn{
        Insn.mov(.r0, 0),
        Insn.exit(),
    };

    const prog = try BPF.prog_load(.socket_filter, &good_prog, null, "MIT", 0);
    _ = try prog_test_run(prog);
    defer std.os.close(prog);
}
