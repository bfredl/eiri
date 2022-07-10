const std = @import("std");
const BPF = std.os.linux.BPF;
const Insn = BPF.Insn;

pub fn main() !void {
    const good_prog = [_]Insn{
        Insn.mov(.r0, 0),
        Insn.exit(),
    };

    const prog = try BPF.prog_load(.socket_filter, &good_prog, null, "MIT", 0);
    defer std.os.close(prog);
}
