const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const Insn = BPF.Insn;

const fd_t = linux.fd_t;
const errno = linux.getErrno;

const p = std.debug.print;

pub fn prog_test_run(
    prog: fd_t,
) !u32 {
    var attr = BPF.Attr{
        .test_run = std.mem.zeroes(BPF.TestRunAttr),
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
pub fn main() !void {
    const good_prog = [_]Insn{
        Insn.mov(.r0, 3),
        Insn.exit(),
    };

    const prog = try BPF.prog_load(.socket_filter, &good_prog, null, "MIT", 0);
    const retval = try prog_test_run(prog);
    p("RETURNERA: {}\n", .{retval});
    defer std.os.close(prog);
}
