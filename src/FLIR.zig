const std = @import("std");
const math = std.math;
const mem = std.mem;
const Allocator = mem.Allocator;
const Self = @This();
const print = std.debug.print;
const SSA_GVN = @import("./SSA_GVN.zig");
const bpfUtil = @import("./bpfUtil.zig");
const BPF = std.os.linux.BPF;

const builtin = @import("builtin");
// const stage2 = builtin.zig_backend != .stage1;
const ArrayList = std.ArrayList;
const assert = std.debug.assert;

const IPReg = BPF.Insn.Reg;
const AluOp = BPF.Insn.AluOp;
const JmpOp = BPF.Insn.JmpOp;

a: Allocator,
// TODO: unmanage all these:
n: ArrayList(Node),
b: ArrayList(Block),
dfs: ArrayList(u16),
sccorder: ArrayList(u16),
refs: ArrayList(u16),
narg: u16 = 0,
nvar: u16 = 0,
// variables 2.0: virtual registero
nvreg: u16 = 0,

first_call: u16 = NoRef,

// 8-byte slots in stack frame
nslots: u8 = 0,

// filler value for unintialized refs. not a sentinel for
// actually invalid refs!
pub const DEAD: u16 = 0xFEFF;
// For blocks: we cannot have more than 2^14 blocks anyway
// for vars: don't allocate last block!
pub const NoRef: u16 = 0xFFFF;

pub fn uv(s: usize) u16 {
    return @intCast(u16, s);
}

pub const Node = struct {
    s: [2]u16 = .{ 0, 0 }, // sucessors
    dfnum: u16 = 0,
    idom: u16 = 0,
    predref: u16 = 0,
    npred: u16 = 0,
    // NB: might be NoRef if the node was deleted,
    // a reachable node must have at least one block even if empty!
    firstblk: u16,
    lastblk: u16,
    dfs_parent: u16 = 0, // TODO: unused
    lowlink: u16 = 0,
    scc: u16 = 0, // XXX: not a topological index, just an identidifer
};

pub const EMPTY: Inst = .{ .tag = .empty, .op1 = 0, .op2 = 0 };

pub const BLK_SIZE = 4;
pub const BLK_SHIFT = 2;
pub const Block = struct {
    node: u16,
    succ: u16 = NoRef,
    i: [BLK_SIZE]Inst = .{EMPTY} ** BLK_SIZE,

    pub fn next(self: @This()) ?u16 {
        return if (self.succ != NoRef) self.succ else null;
    }
};

test "sizey" {
    // @compileLog(@sizeOf(Inst));
    // @compileLog(@sizeOf(Block));
    assert(@sizeOf(Block) <= 64);
}

pub const Inst = struct {
    tag: Tag,
    spec: u8 = 0,
    op1: u16,
    op2: u16,
    // reindex: u16 = 0,
    mckind: MCKind = .unallocated_raw,
    mcidx: u8 = undefined,
    // n_use: u16 = 0,
    last_use: u16 = NoRef,
    // for .call : next call instruction
    // for others: UNUSED
    chain: u16 = NoRef,

    fn free(self: @This()) bool {
        return self.tag == .empty;
    }

    // TODO: handle spec being split between u4 type and u4 somethingelse?
    pub fn spec_type(self: Inst) ValType {
        // TODO: jesus this is terrible
        return if (self.spec >= TODO_INT_SPEC) .intptr else .fpval;
    }

    const TODO_INT_SPEC: u8 = 8;

    const FMODE_MASK: u8 = (1 << 4) - 1;
    const VOP_MASK: u8 = ~FMODE_MASK;

    // pub fn fmode(self: Inst) FMode {
    //     return @intToEnum(FMode, self.spec & FMODE_MASK);
    // }

    pub fn res_type(inst: Inst) ?ValType {
        return switch (inst.tag) {
            .empty => null,
            .arg => inst.spec_type(), // TODO: haIIIII
            .variable => inst.spec_type(), // gets preserved to the phis
            .putvar => null,
            .phi => inst.spec_type(),
            .putphi => null, // stated in the phi instruction
            .constant => inst.spec_type(),
            .alloc => .intptr,
            // .renum => null, // should be removed at this point
            .load => inst.spec_type(),
            .lea => .intptr, // Lea? Who's Lea??
            .store => null,
            .iop => .intptr,
            .icmp => null,
            .ret => null,
            // .vmath => null,
            .load_map => .intptr,
            .call => .intptr,
            .callarg => null,
            .xadd => null,
        };
    }

    pub fn has_res(i: Inst) bool {
        return i.res_type() != null;
    }

    pub fn ipreg(i: Inst) ?IPReg {
        return if (i.mckind == .ipreg) @intToEnum(IPReg, i.mcidx) else null;
    }

    // pub fn avxreg(i: Inst) ?u4 {
    //     return if (i.mckind == .vfreg) @intCast(u4, i.mcidx) else null;
    // }
};
pub const Tag = enum(u8) {
    empty = 0, // empty slot. must not be refered to!
    arg,
    variable,
    alloc, // unconditional stack allocation
    putvar, // non-phi assignment
    phi,
    /// assign to phi of (only) successor
    /// note: despite swearing in the intel church.
    /// op1 is source and op2 is dest, to simplify stuff
    /// i e n_op(putphi) == 1 for the most part
    putphi,
    // renum,
    constant,
    load,
    lea,
    store,
    iop, // imath group?
    icmp, // must be LAST in a node to indicate a cond jump
    // vmath,
    ret,
    load_map,
    call,
    callarg, // XXX: supplying args in %(i+1) for inst with result %i could be messy??
    xadd, // TODO: atomic group
};

pub const MCKind = enum(u8) {
    // not yet allocated, or Inst that trivially produces no value
    unallocated_raw,
    // general purpose register like rax, r12, etc
    ipreg,
    // SSE/AVX registers, ie xmm0/ymm0-15
    vfreg,

    // unallocated, but has a ipreg hint
    unallocated_ipreghint,
    // unallocated, but has a vfreg hint
    unallocated_vfreghint,

    // TODO: support non-uniform sizes of spilled value
    frameslot,
    // unused value, perhaps should have been deleted before alloc
    dead,
    // not stored as such, will be emitted togheter with the next inst
    // example "lea" and then "store", or "load" and then iop/vmath
    fused,

    // constant which is never allocated as such (consumers problem)
    constant,

    pub fn unallocated(self: @This()) bool {
        return switch (self) {
            .unallocated_raw => true,
            .unallocated_ipreghint => true,
            .unallocated_vfreghint => true,
            else => false,
        };
    }
};

// number of op:s which are inst references.
// otherwise they can store whatever data
pub fn n_op(tag: Tag, rw: bool) u2 {
    return switch (tag) {
        .empty => 0,
        .arg => 0,
        .variable => 0,
        // really only one, but we will get rid of this lie
        // before getting into any serious analysis.
        .putvar => 2,
        .phi => 0,
        // works on stage1:
        // .putphi => @as(u2, if (rw) 2 else 1),
        // works on stage2:
        // .putphi => if (rw) 2 else 1,
        // works on both: (clown_emoji)
        .putphi => if (rw) @as(u2, 2) else @as(u2, 1), // TODO: booooooo
        .constant => 0,
        // .renum => 1,
        .load => 1, // base (+- constant off)
        .lea => 1, // base (+- constant off)
        .store => 2, // addr, val
        .iop => 2,
        .icmp => 2,
        // .vmath => 2,
        .ret => 1,
        .call => 2,
        .callarg => 2,
        .alloc => 0,
        .load_map => 0,
        .xadd => 2,
    };
}

pub fn n_op_dyn(i: *Inst, rw: bool) u2 {
    const static_op = n_op(i.tag, rw);
    // TODO: be more strict and consider only insts with optional ops!
    if (static_op == 2 and i.op2 == NoRef) {
        return 1;
    }
    return static_op;
}

// TODO: expand into precise types, like "dword" or "4 packed doubles"
const ValType = enum(u4) {
    intptr = 0,
    fpval,

    pub fn spec(self: @This()) u4 {
        return @enumToInt(self);
    }
};

pub fn next_inst(self: *Self, blk: usize, ii: usize) ?*Inst {
    var b = &self.b.items[blk];
    if (ii + 1 < BLK_SIZE) {
        return &b.i[ii + 1];
    } else {
        const nxt = b.next();
        if (nxt) |n| {
            return &self.b.items[n].i[0];
        } else {
            return null;
        }
    }
}

pub fn init(n: u16, allocator: Allocator) !Self {
    return Self{
        .a = allocator,
        .n = try ArrayList(Node).initCapacity(allocator, n),
        .dfs = ArrayList(u16).init(allocator),
        .sccorder = ArrayList(u16).init(allocator),
        .refs = try ArrayList(u16).initCapacity(allocator, 4 * n),
        .b = try ArrayList(Block).initCapacity(allocator, 2 * n),
    };
}

pub fn deinit(self: *Self) void {
    self.n.deinit();
    self.dfs.deinit();
    self.sccorder.deinit();
    self.refs.deinit();
    self.b.deinit();
}

pub fn toref(blkid: u16, idx: u16) u16 {
    assert(idx < BLK_SIZE);
    return (blkid << BLK_SHIFT) | idx;
}

fn fromref(ref: u16) struct { block: u16, idx: u16 } {
    const IDX_MASK: u16 = BLK_SIZE - 1;
    const BLK_MASK: u16 = ~IDX_MASK;
    return .{
        .block = (ref & BLK_MASK) >> BLK_SHIFT,
        .idx = ref & IDX_MASK,
    };
}

const BIREF = struct { n: u16, i: *Inst };
pub fn biref(self: *Self, ref: u16) ?BIREF {
    if (ref == NoRef) {
        return null;
    }
    const r = fromref(ref);
    const blk = &self.b.items[r.block];
    return BIREF{ .n = blk.node, .i = &blk.i[r.idx] };
}

pub fn iref(self: *Self, ref: u16) ?*Inst {
    return if (self.biref(ref)) |bi| bi.i else null;
}

pub fn addNode(self: *Self) !u16 {
    const n = try self.n.addOne();
    const b = try self.b.addOne();
    var nodeid = uv(self.n.items.len - 1);
    var blkid = uv(self.b.items.len - 1);
    n.* = .{ .firstblk = blkid, .lastblk = blkid };
    b.* = .{ .node = nodeid };
    return nodeid;
}

/// only updates `maybe_pred` if it does not already have a default successor
pub fn addNodeAfter(self: *Self, maybe_pred: u16) !u16 {
    const nodeid = try self.addNode();
    if (self.n.items[maybe_pred].s[0] == 0) {
        self.n.items[maybe_pred].s[0] = nodeid;
    }
    return nodeid;
}

// add inst to the end of block
pub fn addInst(self: *Self, node: u16, inst: Inst) !u16 {
    const n = &self.n.items[node];
    // must exist:
    var blkid = n.lastblk;
    var blk = &self.b.items[blkid];

    // TODO: later we can add more constraints for where "empty" ins can be
    var lastfree: u8 = BLK_SIZE;
    var i: u8 = BLK_SIZE - 1;
    while (true) : (i -= 1) {
        if (blk.i[@intCast(u8, i)].free()) {
            lastfree = i;
        } else {
            break;
        }
        if (i == 0) {
            break;
        }
    }

    if (lastfree == BLK_SIZE) {
        blkid = uv(self.b.items.len);
        blk.succ = blkid;
        blk = try self.b.addOne();
        blk.* = .{ .node = node };
        n.lastblk = blkid;
        lastfree = 0;
    }

    blk.i[lastfree] = inst;
    return toref(blkid, lastfree);
}

// add inst to the beginning of the block, _without_ renumbering any exiting instruction
pub fn preInst(self: *Self, node: u16, inst: Inst) !u16 {
    const n = &self.n.items[node];
    var blkid = n.firstblk;
    var blk = &self.b.items[blkid];

    var firstfree: i8 = -1;
    var i: i8 = 0;
    while (i < BLK_SIZE) : (i += 1) {
        if (blk.i[@intCast(u8, i)].free()) {
            firstfree = i;
        } else {
            break;
        }
    }

    if (firstfree == -1) {
        const nextblk = blkid;
        blkid = uv(self.b.items.len);
        blk = try self.b.addOne();
        blk.* = .{ .node = node, .succ = nextblk };
        n.firstblk = blkid;
        firstfree = BLK_SIZE - 1;
    }

    const free = @intCast(u8, firstfree);

    blk.i[free] = inst;
    return toref(blkid, free);
}

pub fn const_int(self: *Self, node: u16, val: u16) !u16 {
    // TODO: actually store constants in a buffer, or something
    return self.addInst(node, .{ .tag = .constant, .op1 = val, .op2 = 0, .spec = Inst.TODO_INT_SPEC, .mckind = .constant });
}

pub fn alloc(self: *Self, node: u16, size: u8) !u16 {
    if (self.nslots == 255) {
        return error.OutOfMemory; // TODO: yes, but actually no
    }
    const slot = self.nslots + size - 1;
    self.nslots += size;
    return self.addInst(node, .{ .tag = .alloc, .op1 = slot, .op2 = 0, .spec = Inst.TODO_INT_SPEC, .mckind = .fused });
}

pub fn load_map(self: *Self, node: u16, map_fd: u64, value: bool) !u16 {
    // TODO: store the actual u64 map_fd, same place we store actual u64 constants?
    assert(map_fd < 0x10000);
    const low_fd: u16 = @truncate(u16, map_fd);
    return self.addInst(node, .{ .tag = .load_map, .op1 = low_fd, .op2 = 0, .spec = if (value) 1 else 0 });
}

pub fn binop(self: *Self, node: u16, tag: Tag, op1: u16, op2: u16) !u16 {
    return self.addInst(node, .{ .tag = tag, .op1 = op1, .op2 = op2 });
}

pub fn call2(self: *Self, node: u16, func: BPF.Helper, op1: u16, op2: u16) !u16 {
    // TODO: u8 will not fit all helper functions!
    return self.addInst(node, .{ .tag = .call, .op1 = op1, .op2 = op2, .spec = @intCast(u8, @enumToInt(func)) });
}

pub fn call4(self: *Self, node: u16, func: BPF.Helper, op1: u16, op2: u16, op3: u16, op4: u16) !u16 {
    const res = try self.addInst(node, .{ .tag = .call, .op1 = op1, .op2 = op2, .spec = @intCast(u8, @enumToInt(func)) });
    // TODO: indicate number of args in spec somehow? can we get this from BPF.Helper somehow?
    _ = try self.addInst(node, .{ .tag = .callarg, .op1 = op3, .op2 = op4, .spec = 0 });
    return res;
}

pub fn call3(self: *Self, node: u16, func: BPF.Helper, op1: u16, op2: u16, op3: u16) !u16 {
    return call4(self, node, func, op1, op2, op3, NoRef);
}

pub fn iop(self: *Self, node: u16, vop: AluOp, op1: u16, op2: u16) !u16 {
    return self.addInst(node, .{ .tag = .iop, .spec = vop.opx(), .op1 = op1, .op2 = op2 });
}

pub fn icmp(self: *Self, node: u16, cond: JmpOp, op1: u16, op2: u16) !void {
    _ = try self.addInst(node, .{ .tag = .icmp, .spec = @enumToInt(cond), .op1 = op1, .op2 = op2 });
}

pub fn xadd(self: *Self, node: u16, op1: u16, op2: u16) !void {
    _ = try self.addInst(node, .{ .tag = .xadd, .op1 = op1, .op2 = op2 });
}

pub fn putvar(self: *Self, node: u16, op1: u16, op2: u16) !void {
    _ = try self.binop(node, .putvar, op1, op2);
}

pub fn lea(self: *Self, node: u16, base: u16, off: i16) !u16 {
    // FUBBIT: all possible instances of fusing should be detected in analysis anyway
    return self.addInst(node, .{ .tag = .lea, .op1 = base, .op2 = @bitCast(u16, off), .mckind = .fused });
}

pub fn load(self: *Self, node: u16, base: u16, off: i16) !u16 {
    return try self.addInst(node, .{ .tag = .load, .op1 = base, .op2 = @bitCast(u16, off) });
}

pub fn store(self: *Self, node: u16, addr: u16, val: u16) !void {
    _ = try self.addInst(node, .{ .tag = .store, .op1 = addr, .op2 = val, .spec = self.iref(val).?.spec });
}

pub fn ret(self: *Self, node: u16, val: u16) !void {
    _ = try self.addInst(node, .{ .tag = .ret, .op1 = val, .op2 = 0 });
}

pub fn prePhi(self: *Self, node: u16, vref: u16) !u16 {
    const v = self.iref(vref) orelse return error.FLIRError;
    return self.preInst(node, .{ .tag = .phi, .op1 = vref, .op2 = 0, .spec = v.spec });
}

// TODO: maintain wf of block 0: first all args, then all vars.

pub fn arg(self: *Self) !u16 {
    if (self.n.items.len == 0) return error.FLIRError;
    const inst = try self.addInst(0, .{ .tag = .arg, .op1 = self.narg, .op2 = 0, .spec = Inst.TODO_INT_SPEC });
    self.narg += 1;
    return inst;
}

pub fn variable(self: *Self) !u16 {
    if (self.n.items.len == 0) return error.EEEEE;
    const inst = try self.addInst(0, .{ .tag = .variable, .op1 = self.nvar, .op2 = 0, .spec = Inst.TODO_INT_SPEC });
    self.nvar += 1;
    return inst;
}

pub fn empty(self: *Self, ni: u16, allow_succ: bool) bool {
    const node = &self.n.items[ni];
    if (!allow_succ and node.s[0] != 0) return false;
    if (node.firstblk == node.lastblk) {
        const blk = self.b.items[node.firstblk];
        for (blk.i) |i| {
            if (i.tag != .empty) return false;
        }
        assert(node.s[1] == 0);
        return true;
    } else {
        // we assume reorder_inst will kasta empty blocks, true??
        return false;
    }
}

pub fn trivial_succ(self: *Self, ni: u16) ?u16 {
    const node = &self.n.items[ni];
    if (!self.empty(ni, true)) return null;
    return node.s[0];
}

pub fn preds(self: *Self, i: u16) []u16 {
    const v = self.n.items[i];
    return self.refs.items[v.predref..][0..v.npred];
}

fn predlink(self: *Self, i: u16, si: u1, split: bool) !void {
    var n = self.n.items;
    const s = n[i].s[si];
    if (s == 0) return;

    if (split and n[s].npred > 1) {
        const inter = try self.addNode();
        n = self.n.items; // haii
        n[inter].npred = 1;
        n[i].s[si] = inter;
        n[inter].s[0] = s;
        addpred(self, s, inter);
        addpred(self, inter, i);
    } else {
        addpred(self, s, i);
    }
}

fn addpred(self: *Self, s: u16, i: u16) void {
    const n = self.n.items;
    // tricky: build the reflist per node backwards,
    // so the end result is the start index
    if (n[s].predref == 0) {
        self.refs.appendNTimesAssumeCapacity(DEAD, n[s].npred);
        n[s].predref = uv(self.refs.items.len);
    }
    n[s].predref -= 1;
    self.refs.items[n[s].predref] = i;
}

pub fn calc_preds(self: *Self) !void {
    const n = self.n.items;
    // TODO: policy for rebuilding refs from scratch?
    if (self.refs.items.len > 0) unreachable;
    for (n) |v| {
        if (v.s[0] > 0) {
            n[v.s[0]].npred += 1;
        }
        if (v.s[1] > 0 and v.s[1] != v.s[0]) {
            n[v.s[1]].npred += 1;
        }
    }
    for (n) |v, i| {
        const shared = v.s[1] > 0 and v.s[1] == v.s[0];
        if (shared) return error.NotSureAboutThis;
        const split = v.s[1] > 0;
        try self.predlink(@intCast(u16, i), 0, split);
        try self.predlink(@intCast(u16, i), 1, split);
    }
}

pub fn calc_dfs(self: *Self) !void {
    const n = self.n.items;
    var stack = try ArrayList(u16).initCapacity(self.a, n.len);
    try self.dfs.ensureTotalCapacity(n.len);
    defer stack.deinit();
    stack.appendAssumeCapacity(0);
    while (stack.items.len > 0) {
        const v = stack.pop();
        if (n[v].dfnum > 0) {
            // already visited
            continue;
        }
        if (false) print("dfs[{}] = {};\n", .{ self.dfs.items.len, v });
        n[v].dfnum = uv(self.dfs.items.len);
        self.dfs.appendAssumeCapacity(v);

        for (n[v].s) |si| {
            // origin cannot be revisited anyway
            if (si > 0 and n[si].dfnum == 0) {
                n[si].dfs_parent = v;
                stack.appendAssumeCapacity(si);
            }
        }
    }
}

pub fn calc_scc(self: *Self) !void {
    const n = self.n.items;
    try self.dfs.ensureTotalCapacity(n.len);
    var stack = try ArrayList(u16).initCapacity(self.a, n.len);
    defer stack.deinit();
    try self.sccorder.ensureTotalCapacity(n.len);
    self.scc_connect(&stack, 0);
}

pub fn scc_connect(self: *Self, stack: *ArrayList(u16), v: u16) void {
    const n = self.n.items;
    n[v].dfnum = uv(self.dfs.items.len);
    self.dfs.appendAssumeCapacity(v);

    stack.appendAssumeCapacity(v);
    n[v].lowlink = n[v].dfnum;

    for (n[v].s) |w| {
        // origin cannot be revisited anyway
        if (w > 0) {
            if (n[w].dfnum == 0) {
                n[w].dfs_parent = v;
                self.scc_connect(stack, w);
                n[v].lowlink = math.min(n[v].lowlink, n[w].lowlink);
            } else if (n[w].dfnum < n[v].dfnum and n[w].scc == 0) { // or whatever
                n[v].lowlink = math.min(n[v].lowlink, n[w].dfnum);
            }
        }
    }

    if (n[v].lowlink == n[v].dfnum) {
        while (true) {
            const w = stack.pop();
            self.sccorder.appendAssumeCapacity(w);
            // XXX: not topologically sorted, just enables the check: n[i].scc == n[j].scc
            n[w].scc = v;
            if (w == v) break;
        }
    }
}

pub fn reorder_nodes(self: *Self) !void {
    const newlink = try self.a.alloc(u16, self.n.items.len);
    defer self.a.free(newlink);
    mem.set(u16, newlink, NoRef);
    const oldlink = try self.a.alloc(u16, self.n.items.len);
    defer self.a.free(oldlink);
    mem.set(u16, oldlink, NoRef);
    var newpos: u16 = 0;

    var last_scc: u16 = NoRef;
    var cur_scc: u16 = NoRef;

    var sci = self.sccorder.items.len - 1;
    while (true) : (sci -= 1) {
        const old_ni = self.sccorder.items[sci];
        const ni = if (old_ni < newpos) oldlink[old_ni] else old_ni;
        const n = &self.n.items[ni];

        oldlink[newpos] = ni;
        newlink[old_ni] = newpos;

        if (n.scc != last_scc) {
            last_scc = n.scc;
            cur_scc = newpos;
        }
        n.scc = cur_scc;

        mem.swap(Node, n, &self.n.items[newpos]);
        newpos += 1;

        if (sci == 0) break;
    }

    assert(newpos <= self.n.items.len);
    // oopsie woopsie, we killed some dead nodes!
    self.n.items.len = newpos;

    // fixup references:
    for (self.n.items) |*n, ni| {
        for (n.s) |*s| {
            if (s.* != NoRef) {
                s.* = newlink[s.*];
            }
        }

        for (self.preds(uv(ni))) |*pi| {
            pi.* = newlink[pi.*];
        }

        var cur_blk: ?u16 = n.firstblk;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            b.node = uv(ni);

            cur_blk = b.next();
        }
    }
}

// assumes already reorder_nodes !
pub fn reorder_inst(self: *Self) !void {
    const newlink = try self.a.alloc(u16, self.n_ins());
    mem.set(u16, newlink, NoRef);
    const newblkpos = try self.a.alloc(u16, self.b.items.len);
    mem.set(u16, newblkpos, NoRef);
    defer self.a.free(newlink);
    defer self.a.free(newblkpos);
    var newpos: u16 = 0;

    // already in scc order
    for (self.n.items) |*n| {
        var cur_blk: ?u16 = n.firstblk;
        var blklink: ?u16 = null;

        while (cur_blk) |old_blk| {
            // TRICKY: we might have swapped out the block
            const newblk = newpos >> BLK_SHIFT;
            const blk = if (newblkpos[old_blk] != NoRef) newblkpos[old_blk] else old_blk;

            var b = &self.b.items[blk];
            // TODO: RUNDA UPP
            if (blklink) |link| {
                self.b.items[link].succ = newblk;
            } else {
                n.firstblk = newblk;
            }
            blklink = newblk;

            for (b.i) |_, idx| {
                // TODO: compact away .empty, later when opts is punching holes and stuff
                newlink[toref(old_blk, uv(idx))] = newpos;
                newpos += 1;
            }

            if (blk != newblk) {
                const oldval = if (newblkpos[newblk] != NoRef) newblkpos[newblk] else newblk;
                newblkpos[blk] = newblk;
                newblkpos[oldval] = blk;
            }

            cur_blk = b.next();

            mem.swap(Block, b, &self.b.items[newblk]);
            if (cur_blk == null) {
                n.lastblk = newblk;
            }
        }
    }

    // order irrelevant here, just fixing up broken refs
    for (self.n.items) |*n, ni| {
        if (n.dfnum == 0 and ni > 0) {
            // He's dead, Jim!
            n.firstblk = NoRef;
            n.lastblk = NoRef;
            continue;
        }
        var cur_blk: ?u16 = n.firstblk;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            for (b.i) |*i| {
                const nops = n_op_dyn(i, true);
                if (nops > 0) {
                    i.op1 = newlink[i.op1];
                    if (nops > 1) {
                        i.op2 = newlink[i.op2];
                    }
                }
            }
            cur_blk = b.next();
        }
    }
}

// ni = node id of user
pub fn adduse(self: *Self, ni: u16, iuser: u16, used: u16, user: Inst, op: u4) void {
    const ref = self.biref(used).?;
    //ref.i.n_use += 1;
    ref.i.last_use = iuser;
    const argno: ?u4 = switch (user.tag) {
        // TODO: will get wrecked with 5+ args..
        .call => op,
        .callarg => 2 + op,
        .ret => 0,
        else => null,
    };
    if (ref.i.mckind.unallocated()) {
        if (argno) |no| {
            ref.i.mckind = .unallocated_ipreghint;
            ref.i.mcidx = no;
        } else {
            ref.i.mckind = .unallocated_raw;
        }
    }

    // it leaks to another block: could do something here
    if (ref.n != ni) {
        // passs
    }
}

// TODO: not idempotent! does not reset n_use=0 first.
// NB: requires reorder_nodes() [scc] and reorder_inst()
pub fn calc_use(self: *Self) !void {
    var last_call: u16 = NoRef;

    for (self.n.items) |*n, ni| {
        var cur_blk: ?u16 = n.firstblk;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            for (b.i) |*i, idx| {
                const ref = toref(blk, uv(idx));
                if (i.tag == .call) {
                    if (last_call == NoRef) {
                        self.first_call = ref;
                    } else {
                        self.iref(last_call).?.chain = ref;
                    }
                    last_call = ref;
                }

                const nops = n_op_dyn(i, false);
                if (nops > 0) {
                    const useref = if (i.tag == .callarg) last_call else ref;
                    self.adduse(uv(ni), useref, i.op1, i.*, 1);
                    if (nops > 1) {
                        self.adduse(uv(ni), useref, i.op2, i.*, 2);
                    }
                }
            }
            cur_blk = b.next();
        }
    }

    // TODO: inst.last_use is now deceptive if last usage is inside a loop. Then the value lives
    // to the very end of the loop. but we don't implement loops for BPF yet :P
}

pub fn alloc_arg(self: *Self, inst: *Inst) !void {
    _ = self;
    const regs: [6]IPReg = .{ 1, 2, 3, 4, 5 };
    if (inst.op1 >= regs.len) return error.ARA;
    inst.mckind = .ipreg;
    inst.mcidx = regs[inst.op1].id();
}

// fills up some registers, and then goes to the stack.
// reuses op1 if it is from the same block and we are the last user
pub fn trivial_alloc(self: *Self) !void {
    // force analysis of BPF.Insn before BPF.Insn.Reg to work around a stage3 bug
    _ = @sizeOf(BPF.Insn);
    const regs: [4]IPReg = .{ .r6, .r7, .r8, .r9 };
    // const regs: [0]IPReg = .{};
    var used: usize = self.narg;
    for (self.n.items) |*n| {
        var cur_blk: ?u16 = n.firstblk;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            for (b.i) |*i, idx| {
                const ref = toref(blk, uv(idx));
                _ = ref;

                if (false and i.tag == .arg) {
                    return error.OOOOOO;
                    // try self.alloc_arg(i);
                } else if (i.has_res() and i.mckind.unallocated()) {
                    if (i.last_use == NoRef) {
                        // TODO: always safe??
                    } else if (used < regs.len) {
                        i.mckind = .ipreg;
                        i.mcidx = @enumToInt(regs[used]);
                        used += 1;
                    } else {
                        i.mckind = .frameslot;
                        if (self.nslots == 255) {
                            return error.UDunGoofed;
                        }
                        i.mcidx = self.nslots;
                        self.nslots += 1;
                    }
                }
            }
            cur_blk = b.next();
        }
    }
}

pub fn scan_alloc_fwd(self: *Self) !void {
    var active_ipreg: [11]u16 = ([1]u16{0}) ** 11;
    // frame pointer r10 is read-only
    active_ipreg[10] = NoRef;
    // TODO: handle auxilary register properly (by explicit load/spill?)
    active_ipreg[0] = NoRef;

    var next_call = self.first_call;

    for (self.n.items) |*n| {
        var cur_blk: ?u16 = n.firstblk;
        while (cur_blk) |blk| {
            var b = &self.b.items[blk];
            for (b.i) |*i, idx| {
                const ref = toref(blk, uv(idx));
                if (ref == next_call) {
                    assert(i.tag == .call);
                    next_call = i.chain;
                }

                if (false and i.tag == .arg) {
                    try self.alloc_arg(i);
                    assert(active_ipreg[i.mcidx] <= ref);
                    active_ipreg[i.mcidx] = i.last_use;
                } else if (i.has_res() and i.mckind.unallocated() and i.last_use != NoRef) {
                    // const is_avx = (i.res_type() == ValType.fpval);
                    // const regkind: MCKind = if (is_avx) .vfreg else .ipreg;
                    // const the_active = if (is_avx) &active_avx else &active_ipreg;
                    const regkind: MCKind = .ipreg;
                    const the_active = &active_ipreg;

                    // TODO: reghint
                    var regid: ?u4 = null;
                    for (the_active) |l, ri| {
                        if (ri <= 5) {
                            // TODO: be more liberal with scratch register. might be easier in reverse mode
                            // (values which MUST go into args registers r1-r5 get dibs, rest can use them if free)
                            if (!(i.last_use == next_call and i.mckind == .unallocated_ipreghint and i.mcidx == ri)) {
                                continue;
                            }
                        }
                        if (l <= ref) {
                            regid = @intCast(u4, ri);
                            break;
                        }
                    }

                    if (regid) |ri| {
                        i.mckind = regkind;
                        i.mcidx = ri;
                        the_active[ri] = i.last_use;
                    } else {
                        i.mckind = .frameslot;
                        if (self.nslots == 255) {
                            return error.UDunGoofed;
                        }
                        i.mcidx = self.nslots;
                        // TODO: lol reuse slots
                        self.nslots += 1;
                    }
                }
            }
            cur_blk = b.next();
        }
    }
}

/// number of numbered instructions (a lot of these might be empty)
pub fn n_ins(self: *Self) usize {
    return self.b.items.len * BLK_SIZE;
}

pub fn debug_print(self: *Self) void {
    const color_map = self.a.alloc(u8, self.n_ins()) catch @panic("OOM in debug_print");
    defer self.a.free(color_map);
    mem.set(u8, color_map, 0);
    var last_color: u8 = 0;

    print("\n", .{});
    for (self.n.items) |*n, i| {
        print("node {} (npred {}, scc {}):", .{ i, n.npred, n.scc });

        if (n.firstblk == NoRef) {
            print(" VERY DEAD\n", .{});
            continue;
        }

        print("\n", .{});

        const did_ret = self.print_blk(n.firstblk, color_map, &last_color);

        if (n.s[1] == 0) {
            if (n.s[0] == 0) {
                if (!did_ret) print("  diverge\n", .{});
            } else if (n.s[0] != i + 1) {
                print("  jump {}\n", .{n.s[0]});
            }
        } else {
            print("  split: {any}\n", .{n.s});
        }
    }
}

const RGB = struct { r: u8, g: u8, b: u8 };
fn color(fg: bool, rgb: RGB) void {
    const kod = if (fg) "3" else "4";
    print("\x1b[{s}8;2;{};{};{}m", .{ kod, rgb.r, rgb.g, rgb.b });
}

fn reset() void {
    print("\x1b[0m", .{});
}

fn map_color(idx: u8) void {
    switch (idx) {
        0 => reset(),
        1 => color(true, .{ .r = 0x33, .g = 0x55, .b = 0xFF }),
        2 => color(true, .{ .r = 0x11, .g = 0xFF, .b = 0x44 }),
        3 => color(true, .{ .r = 0xFF, .g = 0x00, .b = 0x77 }),
        else => color(false, .{ .r = 0x44, .g = 0x44, .b = 0x44 }),
    }
}

fn print_blk(self: *Self, firstblk: u16, color_map: []u8, last_color: *u8) bool {
    var cur_blk: ?u16 = firstblk;
    var did_ret = false;
    while (cur_blk) |blk| {
        // print("THE BLOCK: {}\n", .{blk});
        var b = &self.b.items[blk];
        for (b.i) |i, idx| {
            if (i.tag == .empty) {
                continue;
            } else if (i.tag == .ret) {
                did_ret = true;
            }
            const ref = toref(blk, uv(idx));
            print_insn(ref, i, color_map, last_color);
            print("\n", .{});
        }
        cur_blk = b.next();
    }
    return did_ret;
}

pub fn print_insn(ref: u16, i: Inst, color_map: []u8, last_color: *u8) void {
    print("  ", .{});
    if (i.mckind != .constant and i.last_use != NoRef) {
        last_color.* += 1;
        const my_color = last_color.*;
        color_map[ref] = my_color;
        map_color(my_color);
    }
    print("%{}", .{ref});
    reset();

    const chr: u8 = if (i.has_res()) '=' else ' ';
    print(" {c} {s}", .{ chr, @tagName(i.tag) });

    if (i.tag == .variable) {
        print(" {s}", .{@tagName(i.spec_type())});
    }

    if (i.tag == .iop) {
        // print(".{s}", .{@tagName(@intToEnum(AluOp, i.spec))});
    } else if (i.tag == .call) {
        color(true, .{ .r = 0xFF, .g = 0xAA, .b = 0x00 });
        print(" {s}", .{@tagName(@intToEnum(BPF.Helper, i.spec))});
    } else if (i.tag == .constant) {
        print(" c[{}]", .{i.op1});
    } else if (i.tag == .putphi) {
        print(" %{} <-", .{i.op2});
    }

    const nop = n_op(i.tag, false);
    if (nop > 0) {
        map_color(color_map[i.op1]);
        print(" %{}", .{i.op1});
        reset();
        if (nop > 1) {
            if (i.op2 == NoRef) {
                print(", %NoRef", .{});
            } else {
                print(", ", .{});
                map_color(color_map[i.op2]);
                print("%{}", .{i.op2});
            }
        }
    }
    print_mcval(i);
    if (i.last_use != NoRef) {
        // this is a compiler bug ("*" emitted for Noref)
        //print(" <{}{s}>", .{ i.n_use, @as([]const u8, if (i.vreg != NoRef) "*" else "") });
        // this is getting ridiculous
        color(true, .{ .r = 128, .g = 128, .b = 128 });
        if (false) { // i.vreg != NoRef
            // print(" |{}=>%{}|", .{ i.vreg, i.last_use });
        } else {
            print(" <%{}>", .{i.last_use});
        }
        reset();
        // print(" <{}{s}>", .{ i.last_use, marker });
        //print(" <{}:{}>", .{ i.n_use, i.vreg });
    }
}

fn print_mcval(i: Inst) void {
    color(true, .{ .r = 128, .g = 128, .b = 128 });
    switch (i.mckind) {
        .frameslot => print(" [r10-8*{}]", .{i.mcidx + 1}),
        .ipreg => print(" $r{}", .{i.mcidx}),
        .vfreg => print(" $ymm{}", .{i.mcidx}),
        else => {
            if (i.tag == .load or i.tag == .phi or i.tag == .arg) {
                if (i.res_type()) |t| {
                    print(" {s}", .{@tagName(t)});
                }
            }
        },
    }
    reset();
}

const test_allocator = std.testing.allocator;
const expectEqual = std.testing.expectEqual;

pub fn test_analysis(self: *Self, comptime check: bool) !void {
    if (check) try self.check_cfg_valid();
    try self.calc_preds();

    try self.calc_scc(); // also provides dfs
    try self.reorder_nodes();
    if (check) try self.check_cfg_valid();
    try SSA_GVN.ssa_gvn(self);

    try self.reorder_inst();
    if (check) try self.check_cfg_valid();
    try self.calc_use();
    // try self.trivial_alloc();
    try self.scan_alloc_fwd();

    if (check) try self.check_cfg_valid();
    try self.remove_empty();
    if (check) try self.check_cfg_valid();
}

pub fn remove_empty(self: *Self) !void {
    for (self.n.items) |*n, ni| {
        for (n.s) |*s| {
            if (s.* == 0) continue;
            const fallthrough = self.trivial_succ(s.*);
            if (fallthrough) |f| {
                const b = &self.n.items[s.*];
                b.npred = 0;
                s.* = f;
                self.addpred(f, @intCast(u16, ni));
            }
        }
    }
}

pub fn get_jmp_or_last(self: *Self, n: *Node) !?Tag {
    var cur_blk: ?u16 = n.firstblk;
    var last_inst: ?Tag = null;
    while (cur_blk) |blk| {
        var b = &self.b.items[blk];
        for (b.i) |i| {
            if (i.tag == .empty) {
                continue;
            }
            if (last_inst) |l| if (l == .icmp or l == .ret) return error.InvalidCFG;
            last_inst = i.tag;
        }
        cur_blk = b.next();
    }
    return last_inst;
}

/// does not use or verify node.npred
pub fn check_cfg_valid(self: *Self) !void {
    const reached = try self.a.alloc(bool, self.n.items.len);
    defer self.a.free(reached);
    mem.set(bool, reached, false);
    for (self.n.items) |*n| {
        for (n.s) |s| {
            if (s > self.n.items.len) return error.InvalidCFG;
            reached[s] = true;
        }
    }
    for (self.n.items) |*n, ni| {
        const last = try self.get_jmp_or_last(n);
        if ((last == Tag.icmp) != (n.s[1] != 0)) return error.InvalidCFG;
        if (last == Tag.ret and n.s[0] != 0) return error.InvalidCFG;
        if (n.s[0] == 0 and (last != Tag.ret and reached[ni])) return error.InvalidCFG;
        // TODO: also !reached and n.s[0] != 0 (not verified by remove_empty)
        if (!reached[ni] and (last != null)) return error.InvalidCFG;
    }
}

test "cfg: simple" {
    var ir = try init(4, test_allocator);
    defer ir.deinit();
    const start = try ir.addNode();
    const doit = try ir.addNodeAfter(start);
    const end = try ir.addNodeAfter(doit);
    const const_0 = try ir.const_int(end, 0);
    try ir.ret(end, const_0);
    try ir.test_analysis(true);
}

test "cfg: branch" {
    var ir = try init(4, test_allocator);
    defer ir.deinit();

    const start = try ir.addNode();
    const ctx = try ir.arg();
    const const_0 = try ir.const_int(start, 0);
    try ir.icmp(start, .jeq, ctx, const_0);
    const doit = try ir.addNodeAfter(start);
    const const_1 = try ir.const_int(doit, 1);
    try ir.xadd(doit, ctx, const_1);
    const end = try ir.addNodeAfter(doit);
    try ir.ret(end, const_0);
    ir.n.items[start].s[1] = end;

    try ir.test_analysis(true);
}
