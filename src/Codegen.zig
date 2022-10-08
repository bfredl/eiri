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
const I = Insn;

code: ArrayList(Insn),
const Self = @This();

const EAddr = struct { reg: u4, off: i16 };

pub fn dump(self: *Self) void {
    for (self.code.items) |*i, ni| {
        dump_ins(i.*, ni);
    }
}

pub fn dump_ins(i: I, ni: usize) void {
    print("{}: {x} ", .{ ni, i.code });
    const grp = switch (@intCast(u3, i.code & 0x07)) {
        BPF.LD => "LD",
        BPF.LDX => "LDX",
        BPF.ST => "ST",
        BPF.STX => "STX",
        BPF.ALU => "ALU",
        BPF.JMP => "JMP",
        BPF.RET => "RET",
        BPF.MISC => "A8M", // ALU64 or MISC
    };
    print("{s}", .{grp});

    const aluspec = switch (i.code & 0xf0) {
        BPF.ADD => "ADD",
        BPF.SUB => "SUB",
        BPF.MUL => "MUL",
        BPF.DIV => "DIV",
        BPF.OR => "OR",
        BPF.AND => "AND",
        BPF.LSH => "LSH",
        BPF.RSH => "RSH",
        BPF.NEG => "NEG",
        BPF.MOD => "MOD",
        BPF.XOR => "XOR",
        BPF.MOV => "MOV",
        BPF.ARSH => "ARSH",
        else => "???",
    };
    switch (@intCast(u4, i.code & 0x0f)) {
        BPF.ALU => {
            print(".{s}", .{aluspec});
        },
        BPF.ALU64 => {
            print(".{s}", .{aluspec});
        },
        else => {},
    }
    print(" d{} s{} o{} i{}\n", .{ i.dst, i.src, i.off, i.imm });
}

pub fn get_target(self: *Self) u32 {
    return @intCast(u32, self.code.items.len);
}

pub fn set_target(self: *Self, pos: u32) void {
    var off = self.get_target() - (pos + 1);
    self.code.items[pos].off = @intCast(i16, off);
}

pub fn put(self: *Self, insn: Insn) !void {
    dump_ins(insn, self.code.items.len);
    try self.code.append(insn);
}

pub fn slotoff(slotid: anytype) i16 {
    return -8 * (1 + @intCast(i16, slotid));
}

pub fn ld_map_fd(self: *Self, reg: IPReg, map_fd: fd_t) !void {
    try self.put(I.ld_map_fd1(reg, map_fd));
    try self.put(I.ld_map_fd2(map_fd));
}

pub fn jeq(self: *Self, src: IPReg, dst: anytype) !u32 {
    var pos = self.get_target();
    try self.put(I.jeq(src, dst, -0x7FFF));
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

fn mov(self: *Self, dst: IPReg, src: anytype) !void {
    try self.put(I.mov(dst, src));
}

fn regmovmc(self: *Self, dst: IPReg, src: Inst) !void {
    switch (src.mckind) {
        .frameslot => try self.put(I.ldx(.double_word, dst, .r10, -8 * @as(i16, src.mcidx))),
        .ipreg => {
            const reg = @intToEnum(IPReg, src.mcidx);
            if (dst != reg) try self.mov(dst, reg);
        },
        .constant => {
            if (src.tag != .constant) return error.TheDinnerConversationIsLively;
            try self.mov(dst, src.op1);
        },
        .fused => {
            unreachable;
        },
        else => return error.AAA_AA_A,
    }
}

fn regjmpmc(self: *Self, dst: IPReg, src: Inst) !u32 {
    switch (src.mckind) {
        .frameslot => {
            unreachable;
            // try self.put(I.ldx(.double_word, dst, .r10, -8 * @as(i16, src.mcidx))),
        },
        .ipreg => {
            // const reg = @intToEnum(IPReg, src.mcidx);
            // if (dst != reg) try self.mov(dst, reg);
            unreachable;
        },
        .constant => {
            if (src.tag != .constant) return error.TheDinnerConversationIsLively;
            const pos = self.get_target();
            try self.put(I.jle(dst, src.op1, 0x7FFF));
            return pos;
        },
        .fused => {
            unreachable;
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

fn mcmovreg(self: *Self, dst: Inst, src: IPReg) !void {
    switch (dst.mckind) {
        .frameslot => try self.put(I.stx(.double_word, .r10, slotoff(dst.mcidx), src)),
        .ipreg => {
            const reg = @intToEnum(IPReg, dst.mcidx);
            if (reg != src) try self.mov(reg, src);
        },
        else => return error.AAA_AA_A,
    }
}

fn mcmovi(self: *Self, i: Inst) !void {
    switch (i.mckind) {
        .frameslot => {
            // TODO: just store??
            try self.put(I.mov(.r0, i.op1));
            try self.mcmovreg(i, .r0);
        },
        .ipreg => {
            const reg = @intToEnum(IPReg, i.mcidx);
            try self.mov(reg, i.op1);
        },
        .fused => {}, // let user lookup value
        .constant => {}, // let user lookup value
        else => return error.AAA_AA_A,
    }
}

fn stx(self: *Self, dst: EAddr, src: IPReg) !void {
    try self.put(I.stx(.double_word, @intToEnum(IPReg, dst.reg), dst.off, src));
}

fn st(self: *Self, dst: EAddr, src: anytype) !void {
    // TODO: AAAA wrong size
    try self.put(I.st(.word, @intToEnum(IPReg, dst.reg), dst.off, src));
}

fn addrmovmc(self: *Self, dst: EAddr, src: Inst) !void {
    switch (src.mckind) {
        .constant => {
            if (src.tag != .constant) unreachable;
            try self.st(dst, src.op1);
        },
        .ipreg => {
            try self.stx(dst, @intToEnum(IPReg, src.mcidx));
        },
        else => unreachable,
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
        // try cfo.jbck(cond, labels[succ]);
        unreachable;
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
    // try cfo.enter();

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
                cfo.set_target(targets[pred][si]);
                targets[pred][si] = 0;
            }
        }

        var cur_blk: ?u16 = n.firstblk;
        // var ea_fused: Self.EAddr = undefined;
        var fused_inst: ?*Inst = null;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            for (b.i) |*i, ii| {
                if (i.tag == .empty) continue;

                print("%{}: \n", .{FLIR.toref(blk, uv(ii))});

                var was_fused: bool = false;
                switch (i.tag) {
                    // empty doesn't flush fused value
                    .empty => continue,
                    .ret => try regmovmc(cfo, .r0, self.iref(i.op1).?.*),
                    .iop => {
                        const dst = i.ipreg() orelse .r0;
                        try regmovmc(cfo, dst, self.iref(i.op1).?.*);
                        // try regaritmc(cfo, @intToEnum(bpfUtil.AluOp, i.spec), dst, self.iref(i.op2).?.*);
                        try mcmovreg(cfo, i.*, dst); // elided if dst is register
                        unreachable;
                    },
                    .constant => try mcmovi(cfo, i.*),
                    .ilessthan => {
                        const firstop = self.iref(i.op1).?.ipreg() orelse .r0;
                        const pos = try regjmpmc(cfo, firstop, self.iref(i.op2).?.*);
                        targets[ni][1] = pos;
                        // try regaritmc(cfo, .cmp, firstop, self.iref(i.op2).?.*);
                        unreachable;
                    },
                    .putphi => {
                        // TODO: actually check for parallell-move conflicts
                        // either here or as an extra deconstruction step
                        try movmcs(cfo, self.iref(i.op2).?.*, self.iref(i.op1).?.*, .r0);
                    },
                    .load => {
                        // TODO: spill spall supllit?
                        const base = self.iref(i.op1).?.ipreg() orelse unreachable;
                        const idx = self.iref(i.op2).?.ipreg() orelse unreachable;
                        _ = base;
                        _ = idx;
                        // const eaddr = unreachable; // Self.qi(base, idx);
                        if (i.spec_type() == .intptr) {
                            const dst = i.ipreg() orelse .r0;
                            // try cfo.movrm(dst, eaddr);
                            try mcmovreg(cfo, i.*, dst); // elided if dst is register
                            unreachable;
                        }
                    },
                    .lea => {
                        // TODO: spill spall supllit?
                        const base = self.iref(i.op1).?.ipreg() orelse unreachable;
                        const idx = self.iref(i.op2).?.ipreg() orelse unreachable;
                        _ = base;
                        _ = idx;
                        // const eaddr = Self.qi(base, idx);
                        if (i.mckind == .fused) {
                            // ea_fused = eaddr;
                            was_fused = true;
                        } else {
                            const dst = i.ipreg() orelse .r0;
                            // try cfo.lea(dst, Self.qi(base, idx));
                            try mcmovreg(cfo, i.*, dst); // elided if dst is register
                            unreachable;
                        }
                    },
                    .store => {
                        // TODO: fuse lea with store
                        const addr = self.iref(i.op1).?;
                        // const eaddr = if (addr == fused_inst)
                        //     ea_fused
                        // else
                        //     Self.a(self.iref(i.op1).?.ipreg() orelse unreachable);
                        const eaddr: EAddr = if (addr.tag == .alloc) .{ .reg = 10, .off = slotoff(addr.op1) } else if (addr.mckind == .ipreg) .{ .reg = @intCast(u4, addr.mcidx), .off = 0 } else unreachable;
                        const val = self.iref(i.op2).?;
                        try addrmovmc(cfo, eaddr, val.*);
                    },
                    .load_map_fd => {
                        const reg = if (i.mckind == .ipreg) @intToEnum(IPReg, i.mcidx) else .r0;
                        try ld_map_fd(cfo, reg, i.op1);
                        try mcmovreg(cfo, i.*, reg);
                    },
                    .alloc => {},
                    .call2 => {
                        try regmovmc(cfo, .r1, self.iref(i.op1).?.*);
                        try regmovmc(cfo, .r2, self.iref(i.op2).?.*);
                        try cfo.put(I.call(@intToEnum(BPF.Helper, i.spec)));
                        try mcmovreg(cfo, i.*, .r0);
                    },
                    else => {
                        print("TEG! {}\n", .{i.tag});
                        unreachable;
                    },
                }
                fused_inst = if (was_fused) i else null;
            }
            cur_blk = b.next();
        }

        // TODO: handle trivial critical-edge block.
        const fallthru = ni + 1;
        if (n.s[0] == fallthru and n.s[1] != 0) {
            // TOTO: assert  last instruction was a cond jmp!

            // try makejmp(self, cfo, .nl, uv(ni), 1, labels, targets);
        } else {
            const default: u1 = default: {
                if (n.s[1] != 0) {
                    unreachable;
                    // try makejmp(self, cfo, .l, uv(ni), 0, labels, targets);
                    // break :default 1;
                } else break :default 0;
            };

            if (n.s[default] != fallthru and n.s[default] != 0) {
                // try makejmp(self, cfo, null, uv(ni), default, labels, targets);
                unreachable;
            }
        }
    }

    // try cfo.leave();
    try cfo.put(I.exit());
    return target;
}
