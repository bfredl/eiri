const std = @import("std");
const mem = std.mem;
const FLIR = @import("./FLIR.zig");
const bpfUtil = @import("./bpfUtil.zig");
const print = std.debug.print;
const Inst = FLIR.Inst;
const uv = FLIR.uv;
const linux = std.os.linux;
const BPF = linux.BPF;
const IPReg = BPF.Insn.Reg;
const Allocator = mem.Allocator;
const fd_t = linux.fd_t;

const ArrayList = std.ArrayList;

const Insn = BPF.Insn;

code: ArrayList(Insn),
const Self = @This();

pub fn get_target(self: *Self) u32 {
    return @intCast(u32, self.code.items.len);
}

pub fn set_target(self: *Self, pos: u32) void {
    var off = self.get_target() - (pos + 1);
    self.code.items[pos].off = @intCast(i16, off);
}

pub fn put(self: *Self, insn: Insn) !void {
    try self.code.append(insn);
}

pub fn ld_map_fd1(self: *Self, reg: IPReg, map_fd: fd_t) !void {
    try self.put(Insn.ld_map_fd1(reg, map_fd));
    try self.put(Insn.ld_map_fd2(map_fd));
}

pub fn jeq(self: *Self, src: IPReg, dst: anytype) !u32 {
    var pos = self.get_target();
    try self.put(Insn.jeq(src, dst, -0x7FFF));
    return pos;
}

pub fn init(allocator: Allocator) !Self {
    return Self{
        .code = try ArrayList(Insn).initCapacity(allocator, 128),
    };
}

pub fn prog(self: Self) []Insn {
    return self.code.items;
}

fn regmovmc(cfo: *Self, dst: IPReg, src: Inst) !void {
    switch (src.mckind) {
        .frameslot => try cfo.movrm(dst, Self.a(.rbp).o(-8 * @as(i32, src.mcidx))),
        .ipreg => {
            const reg = @intToEnum(IPReg, src.mcidx);
            if (dst != reg) try cfo.mov(dst, reg);
        },
        .fused => {
            if (src.tag != .constant) return error.TheDinnerConversationIsLively;
            if (src.op1 != 0) { // TODO: proper constval
                try cfo.movri(dst, src.op1);
            } else {
                // THANKS INTEL
                try cfo.arit(.xor, dst, dst);
            }
        },
        else => return error.AAA_AA_A,
    }
}

fn regaritmc(cfo: *Self, op: bpfUtil.AluOp, dst: IPReg, i: Inst) !void {
    switch (i.mckind) {
        .frameslot => try cfo.aritrm(op, dst, Self.a(.rbp).o(-8 * @as(i32, i.mcidx))),
        .ipreg => {
            const reg = @intToEnum(IPReg, i.mcidx);
            try cfo.arit(op, dst, reg);
        },
        .fused => {
            if (i.tag != .constant) return error.GetLostHeIsNeverComingBack;
            try cfo.aritri(op, dst, i.op1); // TODO: proper constval

        },
        else => return error.AAA_AA_A,
    }
}

fn mcmovreg(cfo: *Self, dst: Inst, src: IPReg) !void {
    switch (dst.mckind) {
        .frameslot => try cfo.movmr(Self.a(.rbp).o(-8 * @as(i32, dst.mcidx)), .rax),
        .ipreg => {
            const reg = @intToEnum(IPReg, dst.mcidx);
            if (reg != src) try cfo.mov(reg, src);
        },
        else => return error.AAA_AA_A,
    }
}

fn mcmovi(cfo: *Self, i: Inst) !void {
    switch (i.mckind) {
        .frameslot => try cfo.movmi(Self.a(.rbp).o(-8 * @as(i32, i.mcidx)), i.op1),
        .ipreg => {
            const reg = @intToEnum(IPReg, i.mcidx);
            if (i.op1 != 0) {
                try cfo.movri(reg, i.op1);
            } else {
                // THANKS INTEL
                try cfo.arit(.xor, reg, reg);
            }
        },
        .fused => {}, // let user lookup value
        else => return error.AAA_AA_A,
    }
}

// TODO: obviously better handling of scratch register
fn movmcs(cfo: *Self, dst: Inst, src: Inst, scratch: IPReg) !void {
    if (dst.mckind == src.mckind and dst.mcidx == src.mcidx) {
        return;
    }
    if (dst.mckind == .ipreg) {
        try regmovmc(cfo, @intToEnum(IPReg, dst.mcidx), src);
    } else {
        const reg = if (src.mckind == .ipreg)
            @intToEnum(IPReg, src.mcidx)
        else reg: {
            try regmovmc(cfo, scratch, src);
            break :reg scratch;
        };
        try mcmovreg(cfo, dst, reg);
    }
}

pub fn makejmp(self: *FLIR, cfo: *Self, cond: ?bpfUtil.JmpOp, ni: u16, si: u1, labels: []u32, targets: [][2]u32) !void {
    const succ = self.n.items[ni].s[si];
    // NOTE: we assume blk 0 always has the prologue (push rbp; mov rbp, rsp)
    // at least, so that even if blk 0 is empty, blk 1 has target larger than 0x00
    if (labels[succ] != 0) {
        try cfo.jbck(cond, labels[succ]);
    } else {
        targets[ni][si] = try cfo.jfwd(cond);
    }
}

pub fn codegen(self: *FLIR, cfo: *Self) !u32 {
    var labels = try self.a.alloc(u32, self.dfs.items.len);
    var targets = try self.a.alloc([2]u32, self.dfs.items.len);
    defer self.a.free(labels);
    defer self.a.free(targets);
    mem.set(u32, labels, 0);
    mem.set([2]u32, targets, .{ 0, 0 });

    const target = cfo.get_target();
    try cfo.enter();
    const stacksize = 8 * @as(i32, self.nslots);
    if (stacksize > 0) {
        const padding = (-stacksize) & 0xF;
        // print("size: {}, extrasize: {}\n", .{ stacksize, padding });
        try cfo.aritri(.sub, .rsp, stacksize + padding);
    }

    for (self.n.items) |*n, ni| {
        if (n.dfnum == 0 and ni > 0) {
            // non-entry block not reached by df search is dead.
            // TODO: these should already been cleaned up at this point
            continue;
        }
        labels[ni] = cfo.get_target();
        print("LABEL: {x} {}\n", .{ labels[ni], ni });
        for (self.preds(uv(ni))) |pred| {
            const pr = &self.n.items[pred];
            const si: u1 = if (pr.s[0] == ni) 0 else 1;
            if (targets[pred][si] != 0) {
                try cfo.set_target(targets[pred][si]);
                targets[pred][si] = 0;
            }
        }

        var cur_blk: ?u16 = n.firstblk;
        var ea_fused: Self.EAddr = undefined;
        var fused_inst: ?*Inst = null;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            for (b.i) |*i| {
                if (i.tag == .empty) continue;

                var was_fused: bool = false;
                switch (i.tag) {
                    // empty doesn't flush fused value
                    .empty => continue,
                    .ret => try regmovmc(cfo, .rax, self.iref(i.op1).?.*),
                    .iop => {
                        const dst = i.ipreg() orelse .rax;
                        try regmovmc(cfo, dst, self.iref(i.op1).?.*);
                        try regaritmc(cfo, @intToEnum(bpfUtil.AluOp, i.spec), dst, self.iref(i.op2).?.*);
                        try mcmovreg(cfo, i.*, dst); // elided if dst is register
                    },
                    .constant => try mcmovi(cfo, i.*),
                    .ilessthan => {
                        const firstop = self.iref(i.op1).?.ipreg() orelse .rax;
                        try regmovmc(cfo, firstop, self.iref(i.op1).?.*);
                        try regaritmc(cfo, .cmp, firstop, self.iref(i.op2).?.*);
                    },
                    .putphi => {
                        // TODO: actually check for parallell-move conflicts
                        // either here or as an extra deconstruction step
                        try movmcs(cfo, self.iref(i.op2).?.*, self.iref(i.op1).?.*, .rax);
                    },
                    .load => {
                        // TODO: spill spall supllit?
                        const base = self.iref(i.op1).?.ipreg() orelse unreachable;
                        const idx = self.iref(i.op2).?.ipreg() orelse unreachable;
                        const eaddr = Self.qi(base, idx);
                        if (i.spec_type() == .intptr) {
                            const dst = i.ipreg() orelse .rax;
                            try cfo.movrm(dst, eaddr);
                            try mcmovreg(cfo, i.*, dst); // elided if dst is register
                        } else {
                            const dst = i.avxreg() orelse unreachable;
                            try cfo.vmovurm(i.fmode(), dst, eaddr);
                        }
                    },
                    .lea => {
                        // TODO: spill spall supllit?
                        const base = self.iref(i.op1).?.ipreg() orelse unreachable;
                        const idx = self.iref(i.op2).?.ipreg() orelse unreachable;
                        const eaddr = Self.qi(base, idx);
                        if (i.mckind == .fused) {
                            ea_fused = eaddr;
                            was_fused = true;
                        } else {
                            const dst = i.ipreg() orelse .rax;
                            try cfo.lea(dst, Self.qi(base, idx));
                            try mcmovreg(cfo, i.*, dst); // elided if dst is register
                        }
                    },
                    .store => {
                        // TODO: fuse lea with store
                        const addr = self.iref(i.op1).?;
                        const eaddr = if (addr == fused_inst)
                            ea_fused
                        else
                            Self.a(self.iref(i.op1).?.ipreg() orelse unreachable);
                        const val = self.iref(i.op2).?;
                        if (val.res_type().? == .intptr) {
                            unreachable;
                        } else {
                            const src = val.avxreg() orelse unreachable;
                            try cfo.vmovumr(i.fmode(), eaddr, src);
                        }
                    },
                    .vmath => {
                        const x = self.iref(i.op1).?.avxreg() orelse unreachable;
                        const y = self.iref(i.op2).?.avxreg() orelse unreachable;
                        const dst = i.avxreg() orelse unreachable;
                        try cfo.vmathf(i.vop(), i.fmode(), dst, x, y);
                    },

                    else => {},
                }
                fused_inst = if (was_fused) i else null;
            }
            cur_blk = b.next();
        }

        // TODO: handle trivial critical-edge block.
        const fallthru = ni + 1;
        if (n.s[0] == fallthru and n.s[1] != 0) {
            try makejmp(self, cfo, .nl, uv(ni), 1, labels, targets);
        } else {
            const default: u1 = default: {
                if (n.s[1] != 0) {
                    try makejmp(self, cfo, .l, uv(ni), 0, labels, targets);
                    break :default 1;
                } else break :default 0;
            };

            if (n.s[default] != fallthru and n.s[default] != 0) {
                try makejmp(self, cfo, null, uv(ni), default, labels, targets);
            }
        }
    }

    try cfo.leave();
    try cfo.ret();
    return target;
}
