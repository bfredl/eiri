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
const options = &@import("root").options;

const EAddr = struct {
    reg: u4,
    off: i16,
    fn with_off(self: EAddr, off: i16) EAddr {
        return .{ .reg = self.reg, .off = self.off + off };
    }
};

fn get_eaddr(self: *FLIR, i: FLIR.Inst, comptime may_lea: bool) !EAddr {
    if (may_lea and i.tag == .lea) {
        const base = self.iref(i.op1).?.*;
        const baseval = try get_eaddr(self, base, false);
        const off = @bitCast(i16, i.op2);
        return baseval.with_off(off);
    } else if (i.mckind == .ipreg) {
        return .{ .reg = @intCast(u4, i.mcidx), .off = 0 };
    } else if (i.tag == .alloc) {
        return .{ .reg = 10, .off = slotoff(i.op1) };
    } else {
        return error.InvalidAddress;
    }
}

pub fn dump(self: *Self) void {
    for (self.code.items, 0..) |*i, ni| {
        dump_ins(i.*, ni);
    }
}

pub fn dump_ins(i: I, ni: usize) void {
    print("{:03}: {x:0>2} ", .{ ni, i.code });
    print("{x} {x} {x:3} {x:4} ", .{ i.dst, i.src, i.off, i.imm });
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

    const h = i.code & 0xf0;
    const aluspec = switch (h) {
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
    const siz = i.code & 0x18;
    const mspec = i.code & 0xe0;
    switch (@intCast(u3, i.code & 0x07)) {
        BPF.ALU, BPF.ALU64 => {
            print("{s}", .{aluspec});
            if (i.code & 0x07 == BPF.ALU64) print("64", .{});
            print(" r{}, ", .{i.dst});
            if (i.code & BPF.X == BPF.X) print("r{}", .{i.src}) else print("{}", .{i.imm});
        },
        BPF.ST, BPF.LD => {
            if (i.code == 0 and i.imm == 0) {
                // TODO: not like this!
                print("\n", .{});
                return;
            }
            _ = siz;
            print("{s} ", .{grp});
            if (mspec == BPF.MEM) {
                print("[r{}{:02}], ", .{ i.dst, i.off });
            } else if (mspec == BPF.IMM and i.src == BPF.PSEUDO_MAP_FD) {
                print("r{}, map_fd ", .{i.dst});
            } else if (mspec == BPF.IMM and i.src == BPF.PSEUDO_MAP_VALUE) {
                print("r{}, map_value ", .{i.dst});
            } else {
                print("?? ", .{});
            }
            print("{}", .{i.imm});
        },
        BPF.STX => {
            _ = siz;
            if (mspec == BPF.MEM) {
                print("STX [r{}{:02}], ", .{ i.dst, i.off });
            } else if (i.code == 0xdb) {
                print("XADD [r{}{:02}], ", .{ i.dst, i.off });
            } else {
                print("STX.?? ", .{});
            }
            print("r{}", .{i.src});
        },
        BPF.LDX => {
            _ = siz;
            print("LDX r{}, ", .{i.dst});
            if (mspec == BPF.MEM) {
                print("[r{}{:02}]", .{ i.src, i.off });
            } else {
                print("???", .{});
            }
        },
        BPF.JMP => {
            const jmpspec = switch (h) {
                BPF.JA => "JA",
                BPF.JEQ => "JEQ",
                BPF.JGT => "JGT",
                BPF.JGE => "JGE",
                BPF.JSET => "JSET",
                BPF.JNE => "JNE",
                BPF.JLT => "JLT",
                BPF.JLE => "JLE",
                BPF.JSGT => "JSGT",
                BPF.JSLT => "JSLT",
                BPF.JSLE => "JSLE",
                else => "J??",
            };

            if (h == BPF.EXIT) {
                print("EXIT ", .{});
            } else if (h == BPF.CALL) {
                print("CALL ${s}", .{@tagName(@intToEnum(BPF.Helper, i.imm))});
            } else {
                print("{s} r{}, ", .{ jmpspec, i.dst });
                if (i.code & BPF.X == BPF.X) print("r{}", .{i.src}) else print("{}", .{i.imm});
                print(" => {}", .{@intCast(i32, ni) + i.off + 1});
            }
        },
        else => print("{s}.???", .{grp}),
    }
    print("\n", .{});
}

pub fn get_target(self: *Self) u32 {
    return @intCast(u32, self.code.items.len);
}

pub fn set_target(self: *Self, pos: u32) void {
    var off = self.get_target() - (pos + 1);
    self.code.items[pos].off = @intCast(i16, off);
}

pub fn put(self: *Self, insn: Insn) !void {
    if (options.dbg_disasm_ir) {
        print("    ", .{});
        dump_ins(insn, self.code.items.len);
    }
    try self.code.append(insn);
}

pub fn slotoff(slotid: anytype) i16 {
    return -8 * (1 + @intCast(i16, slotid));
}

pub fn ld_map_fd(self: *Self, reg: IPReg, map_fd: fd_t, spec: u8) !void {
    var insn = I.ld_map_fd1(reg, map_fd);
    if (spec == 1) { // BPF_PSEUDO_MAP_VALUE
        insn.src = BPF.PSEUDO_MAP_VALUE;
    } else {
        std.debug.assert(spec == 0);
    }
    try self.put(insn);
    // TODO: PSEUDO_MAP_VALUE allows us to code an offset into the second instruction
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
            if (src.tag != .alloc) return error.BBB_BBB;
            try self.mov(dst, .r10);
            try self.put(I.add(dst, slotoff(src.op1)));
        },
        else => return error.AAA_AA_A,
    }
}

fn regjmpmc(self: *Self, op: Insn.JmpOp, dst: IPReg, src: Inst) !u32 {
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
            var inst = I.jmp(op, dst, src.op1, 0x7FFF);
            try self.put(inst);
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
    if (dst.mckind.unallocated()) return;
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
    try self.put(I.st(.double_word, @intToEnum(IPReg, dst.reg), dst.off, src));
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

fn regmovaddr(self: *Self, dst: IPReg, src: EAddr) !void {
    try self.put(I.ldx(.double_word, dst, @intToEnum(IPReg, src.reg), src.off));
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

pub fn makejmp(self: *FLIR, cfo: *Self, op: ?Insn.JmpOp, ni: u16, si: u1, labels: []u32, targets: [][2]u32) !void {
    const succ = self.n.items[ni].s[si];
    // NOTE: we assume blk 0 always has the prologue (push rbp; mov rbp, rsp)
    // at least, so that even if blk 0 is empty, blk 1 has target larger than 0x00
    if (labels[succ] != 0) {
        // try cfo.jbck(cond, labels[succ]);
        unreachable;
    } else {
        targets[ni][si] = try cfo.jfwd(op);
    }
}

pub fn codegen(self: *FLIR, cfo: *Self) !u32 {
    var labels = try self.a.alloc(u32, self.dfs.items.len);
    var targets = try self.a.alloc([2]u32, self.dfs.items.len);

    const color_map = self.a.alloc(u8, self.n_ins()) catch @panic("OOM in debug_print");
    defer self.a.free(color_map);
    mem.set(u8, color_map, 0);
    var last_color: u8 = 0;

    defer self.a.free(labels);
    defer self.a.free(targets);
    mem.set(u32, labels, 0);
    mem.set([2]u32, targets, .{ 0, 0 });

    const target = cfo.get_target();
    // try cfo.enter();

    for (self.n.items, 0..) |*n, ni| {
        if ((n.dfnum == 0 or n.npred == 0) and ni > 0) {
            // non-entry block not reached by df search is dead.
            // TODO: these should already been cleaned up at this point
            // TODO: n.npred explicitly being set to 0 is a hack!
            continue;
        }
        labels[ni] = cfo.get_target();
        // print("LABEL: {x} {}\n", .{ labels[ni], ni });
        for (self.preds(uv(ni))) |pred| {
            const pr = &self.n.items[pred];
            const si: u1 = if (pr.s[0] == ni) 0 else 1;
            if (targets[pred][si] != 0) {
                cfo.set_target(targets[pred][si]);
                targets[pred][si] = 0;
            }
        }

        var fallthru = ni + 1;
        while (fallthru < self.n.items.len and self.n.items[fallthru].npred == 0) {
            fallthru += 1;
        }
        var default_branch: u8 = 0;

        var cur_blk: ?u16 = n.firstblk;
        // var ea_fused: Self.EAddr = undefined;
        var fused_inst: ?*Inst = null;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            for (b.i, 0..) |*i, ii| {
                if (i.tag == .empty) continue;

                if (options.dbg_disasm_ir) {
                    FLIR.print_insn(FLIR.toref(blk, uv(ii)), i.*, color_map, &last_color);
                    print("\n", .{});
                }

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
                    .icmp => {
                        const firstop = self.iref(i.op1).?.ipreg() orelse .r0;
                        var spec = @intToEnum(Insn.JmpOp, i.spec);
                        var taken: u1 = 1;

                        // TODO: this should have been optimized earlier!
                        if (n.s[1] == fallthru and n.s[0] != 0) {
                            if (spec == .jeq) {
                                spec = .jne;
                            } else {
                                unreachable;
                            }
                            default_branch = 1;
                            taken = 0;
                        }

                        const pos = try regjmpmc(cfo, spec, firstop, self.iref(i.op2).?.*);
                        targets[ni][taken] = pos;
                    },
                    .putphi => {
                        // TODO: actually check for parallell-move conflicts
                        // either here or as an extra deconstruction step
                        try movmcs(cfo, self.iref(i.op2).?.*, self.iref(i.op1).?.*, .r0);
                    },
                    .load => {
                        // TODO: spill spall supllit?
                        const addr = self.iref(i.op1).?.*;
                        const off = @intCast(i16, i.op2);
                        const eaddr: EAddr = (try get_eaddr(self, addr, false)).with_off(off);
                        const dst = i.ipreg() orelse .r0;
                        try cfo.regmovaddr(dst, eaddr);
                        try mcmovreg(cfo, i.*, dst); // elided if dst is register
                    },
                    .lea => {
                        // TODO: keep track of lifetime extensions of fused values somewhere
                        if (i.mckind == .fused) {
                            was_fused = true;
                        } else {
                            unreachable;
                        }
                    },
                    .store => {
                        const addr = self.iref(i.op1).?.*;
                        const eaddr: EAddr = try get_eaddr(self, addr, true);
                        const val = self.iref(i.op2).?;
                        try addrmovmc(cfo, eaddr, val.*);
                    },
                    .load_map => {
                        const reg = if (i.mckind == .ipreg) @intToEnum(IPReg, i.mcidx) else .r0;
                        try ld_map_fd(cfo, reg, i.op1, i.spec);
                        try mcmovreg(cfo, i.*, reg);
                    },
                    .alloc => {},
                    .call => {
                        try regmovmc(cfo, .r1, self.iref(i.op1).?.*);
                        try regmovmc(cfo, .r2, self.iref(i.op2).?.*);
                        const nexti = self.next_inst(blk, ii);
                        if (nexti) |iarg| {
                            if (iarg.tag == .callarg) {
                                try regmovmc(cfo, .r3, self.iref(iarg.op1).?.*);
                                if (iarg.op2 != FLIR.NoRef) {
                                    try regmovmc(cfo, .r4, self.iref(iarg.op2).?.*);
                                }
                            }
                        }
                        try cfo.put(I.call(@intToEnum(BPF.Helper, i.spec)));
                        try mcmovreg(cfo, i.*, .r0);
                    },
                    .xadd => {
                        const dest = self.iref(i.op1).?.*;
                        const dest_addr = try get_eaddr(self, dest, true);
                        const src = self.iref(i.op2).?.*;
                        // TODO: regalloc should alloc even a constant
                        const sreg = if (src.mckind == .ipreg) @intToEnum(IPReg, src.mcidx) else .r0;
                        try regmovmc(cfo, sreg, src);
                        var insn = I.xadd(@intToEnum(IPReg, dest_addr.reg), sreg);
                        // TODO: if this works, upstream!
                        insn.off = dest_addr.off;
                        try cfo.put(insn);
                    },
                    .callarg => {
                        // already handled in .call
                    },
                    .arg => {
                        if (i.op1 != 0) unreachable;
                        try mcmovreg(cfo, i.*, .r1);
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

        if (n.s[default_branch] != fallthru and n.s[default_branch] != 0) {
            const pos = cfo.get_target();
            try cfo.put(I.ja(0x7FFF)); // unconditional
            targets[ni][default_branch] = pos;
        }
        // TODO: port handling trivial critical-edge block back to forklift!.
    }

    // try cfo.leave();
    try cfo.put(I.exit());
    return target;
}
