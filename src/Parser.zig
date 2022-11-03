str: []const u8,
pos: usize,

fd_objs: std.StringHashMap(union(enum) {
    map: struct {
        fd: fd_t,
        key_size: usize,
        val_size: usize,
        entries: usize,
    },
    prog: struct { fd: fd_t },
    elf: struct {
        fname: []const u8,
        syms: ElfSymbols,
        sdts: ArrayList(ElfSymbols.Stapsdt),
    },
}),
allocator: Allocator,

pub fn init(str: []const u8, allocator: Allocator) Self {
    return .{
        .str = str,
        .pos = 0,
        .fd_objs = @TypeOf(init(str, allocator).fd_objs).init(allocator),
        .allocator = allocator,
    };
}

const Self = @This();

const std = @import("std");
const print = std.debug.print;
const mem = std.mem;
const Allocator = mem.Allocator;
const meta = std.meta;
const ArrayList = std.ArrayList;

const options = &@import("root").options;

const ElfSymbols = @import("./ElfSymbols.zig");
const FLIR = @import("./FLIR.zig");
const bpfUtil = @import("./bpfUtil.zig");
const BPF = std.os.linux.BPF;
const Codegen = @import("./Codegen.zig");

const fd_t = std.os.fd_t;

fn nonws(self: *Self) ?u8 {
    while (self.pos < self.str.len) : (self.pos += 1) {
        if (self.str[self.pos] != ' ') {
            return self.str[self.pos];
        }
    }
    return null;
}

fn lbrk(self: *Self) ParseError!void {
    const val = self.nonws();
    if (val) |v| {
        if (v != '\n') return error.ParseError;
        self.pos += 1;
    }
}

fn idlike(c: u8) bool {
    return ('a' <= c and c <= 'z') or ('A' <= c and c <= 'Z') or ('0' < c and c < '9') or c == '_';
}

const Chunk = []const u8;
fn keyword(self: *Self) ?Chunk {
    const c = self.nonws() orelse return null;
    if (!('a' <= c and c <= 'z') and !('A' <= c and c <= 'Z')) return null;
    const start = self.pos;
    while (self.pos < self.str.len) : (self.pos += 1) {
        const next = self.str[self.pos];
        if (!idlike(next)) {
            break;
        }
    }
    return self.str[start..self.pos];
}

fn prefixed(self: *Self, sigil: u8) ParseError!?Chunk {
    if (self.nonws() != sigil) return null;
    self.pos += 1;
    return try self.identifier();
}

fn objname(self: *Self) ParseError!?Chunk {
    return self.prefixed('$');
}

fn varname(self: *Self) ParseError!?Chunk {
    return self.prefixed('%');
}

fn labelname(self: *Self) ParseError!?Chunk {
    return self.prefixed(':');
}

fn identifier(self: *Self) ParseError!Chunk {
    const start = self.pos;
    while (self.pos < self.str.len) : (self.pos += 1) {
        const next = self.str[self.pos];
        if (!idlike(next)) {
            break;
        }
    }
    if (self.pos == start) return error.ParseError;
    return self.str[start..self.pos];
}

fn num(self: *Self) ?u32 {
    const first = self.nonws() orelse return null;
    if (!('0' <= first and first <= '9')) return null;
    var val: u32 = 0;
    while (self.pos < self.str.len) : (self.pos += 1) {
        const next = self.str[self.pos];
        if ('0' <= next and next <= '9') {
            val = val * 10 + (next - '0');
        } else {
            break;
        }
    }
    return val;
}

const ParseError = error{ ParseError, OutOfMemory, FLIRError };
fn require(val: anytype, what: []const u8) ParseError!@TypeOf(val.?) {
    return val orelse {
        print("missing {s}\n", .{what});
        return error.ParseError;
    };
}

pub fn parse(self: *Self) !void {
    while (self.nonws()) |next| {
        if (next == '\n') {
            self.pos += 1;
            continue;
        }
        try self.toplevel();
    }
}

pub fn toplevel(self: *Self) !void {
    const kw = self.keyword() orelse return;
    if (mem.eql(u8, kw, "map")) {
        const name = try require(try self.objname(), "name");
        const kind = try require(self.keyword(), "kind");
        const key_size = try require(self.num(), "key_size");
        const val_size = try require(self.num(), "val_size");
        const n_entries = try require(self.num(), "n_entries");
        const item = try nonexisting(&self.fd_objs, name, "object $");
        // print("map '{s}' of kind {s}, key={}, val={}\n", .{ name, kind, key_size, val_size });
        const map_kind = meta.stringToEnum(BPF.MapType, kind) orelse {
            print("unknown map kind: '{s}'\n", .{kind});
            return error.ParseError;
        };
        const fd = if (options.sys)
            try BPF.map_create(map_kind, key_size, val_size, n_entries)
        else
            57;
        item.* = .{ .map = .{ .fd = fd, .key_size = key_size, .val_size = val_size, .entries = n_entries } };
    } else if (mem.eql(u8, kw, "elf")) {
        const name = try require(try self.objname(), "name");

        _ = self.nonws() orelse return error.ParseError;
        const start = self.pos;
        while (self.pos < self.str.len) : (self.pos += 1) {
            const next = self.str[self.pos];
            if (next == '\n') {
                break;
            }
        }
        if (self.pos == start) return error.ParseError;

        const item = try nonexisting(&self.fd_objs, name, "object $");
        const fname = self.str[start..self.pos];
        const elf = try ElfSymbols.init(try std.fs.cwd().openFile(fname, .{}));
        const sdts = try elf.get_sdts(self.allocator);
        item.* = .{ .elf = .{ .fname = fname, .syms = elf, .sdts = sdts } };
    } else if (mem.eql(u8, kw, "func")) {
        const name = try require(try self.objname(), "name");
        const license = try require(self.keyword(), "license");
        try self.lbrk();
        print("FUNC '{s}' \n", .{name});
        const item = try nonexisting(&self.fd_objs, name, "object $");
        var func: Func = .{
            .ir = try FLIR.init(4, self.allocator),
            .refs = std.StringHashMap(u16).init(self.allocator),
            .labels = std.StringHashMap(u16).init(self.allocator),
        };
        func.curnode = try func.ir.addNode();
        while (true) {
            if (!try self.stmt(&func)) break;
            try self.lbrk();
        }
        if (options.dbg_raw_ir) {
            func.ir.debug_print();
            print("\n", .{});
        }
        try func.ir.test_analysis(true);
        if (options.dbg_analysed_ir) {
            func.ir.debug_print();
            print("\n", .{});
        }
        var c = try Codegen.init(self.allocator);
        _ = try Codegen.codegen(&func.ir, &c);
        if (options.dbg_disasm) {
            print("\n", .{});
            c.dump();
        }
        const prog = if (options.sys) try bpfUtil.prog_load_verbose(.kprobe, c.prog(), license) else 83;
        item.* = .{ .prog = .{ .fd = prog } };
    } else if (mem.eql(u8, kw, "attach")) {
        const prog_name = try require(try self.objname(), "program");
        const prog = try self.require_obj(prog_name, .prog);
        const probe_fd = try self.get_probe();
        // TODO: would be nice if this works so we don't need ioctls..
        // _ = try bpfUtil.prog_attach_perf(probe_fd, prog.fd);
        if (options.sys) try bpfUtil.perf_attach_bpf(probe_fd, prog.fd);
    } else {
        print("keyworda {?s}\n", .{kw});
        return error.ParseError;
    }
}

fn get_probe(self: *Self) !fd_t {
    _ = self.nonws();
    const kind = try self.identifier();
    if (mem.eql(u8, kind, "kprobe")) {
        _ = self.nonws();
        const func = try self.identifier();
        _ = self.nonws();
        const offset = self.num() orelse 0;

        if (!options.sys) return 55;
        // TODO: share this, like a non-savage
        const kprobe_type = try bpfUtil.getKprobeType();
        return bpfUtil.perf_open_probe_cstr(kprobe_type, func, offset);
    }
    if (mem.eql(u8, kind, "usdt")) {
        const elf_name = try require(try self.objname(), "elf name");
        _ = self.nonws();
        const probe = try self.identifier();
        const elf = try self.require_obj(elf_name, .elf);
        const sdt = try ElfSymbols.test_get_usdt(elf.sdts.items, probe);

        if (!options.sys) return 55;
        // TODO: share this, like a non-savage
        const uprobe_type = try bpfUtil.getUprobeType();
        return bpfUtil.perf_open_probe_cstr(uprobe_type, elf.fname, sdt.h.pc);
    } else {
        return error.ParseError;
    }
}

fn expect_char(self: *Self, char: u8) ParseError!void {
    if (self.nonws() == char) {
        self.pos += 1;
    } else {
        print("expected '{c}'\n", .{char});
        return error.ParseError;
    }
}

const Func = struct {
    ir: FLIR,
    curnode: u16 = FLIR.NoRef,
    refs: std.StringHashMap(u16),
    labels: std.StringHashMap(u16),
};

fn nonexisting(map: anytype, key: []const u8, what: []const u8) ParseError!@TypeOf(map.getPtr(key).?) {
    const item = try map.getOrPut(key);
    if (item.found_existing) {
        print("duplicate {s}{s}!\n", .{ what, key });
        return error.ParseError;
    }
    return item.value_ptr;
}

pub fn require_obj(self: *Self, key: []const u8, comptime what: anytype) ParseError!@TypeOf(@field(self.fd_objs.get(key).?, @tagName(what))) {
    return (try self.get_obj(key, what)) orelse {
        print("undefined object ${s}!\n", .{key});
        return error.ParseError;
    };
}

pub fn get_obj(self: *Self, key: []const u8, comptime what: anytype) ParseError!?@TypeOf(@field(self.fd_objs.get(key).?, @tagName(what))) {
    const object = self.fd_objs.get(key) orelse return null;
    switch (object) {
        what => |obj| return obj,
        else => {
            print("object is not a {s}: ${s}!\n", .{ @tagName(what), key });
            return error.ParseError;
        },
    }
}

fn get_label(f: *Func, name: []const u8, allow_existing: bool) ParseError!u16 {
    const item = try f.labels.getOrPut(name);
    if (item.found_existing) {
        if (!allow_existing and !f.ir.empty(item.value_ptr.*, false)) {
            print("duplicate label :{s}!\n", .{name});
            return error.ParseError;
        }
    } else {
        item.value_ptr.* = try f.ir.addNode();
    }
    return item.value_ptr.*;
}

pub fn stmt(self: *Self, f: *Func) ParseError!bool {
    if (self.keyword()) |kw| {
        if (mem.eql(u8, kw, "end")) {
            return false;
        } else if (mem.eql(u8, kw, "ret")) {
            const retval = try require(try self.call_arg(f), "return value");
            try f.ir.ret(f.curnode, retval);
            return true;
        } else if (mem.eql(u8, kw, "eq")) {
            const dest = try require(try self.call_arg(f), "dest");
            const src = try require(try self.call_arg(f), "src");
            const target = try require(try self.labelname(), "src");
            try f.ir.icmp(f.curnode, .jeq, dest, src);

            // TODO: mark current node as DED, need either a new node or an unconditional jump
            f.ir.n.items[f.curnode].s[1] = try get_label(f, target, true);
            return true;
        } else if (mem.eql(u8, kw, "store")) {
            try self.expect_char('[');
            const dest = try require(try self.call_arg(f), "destination");
            try self.expect_char(']');
            const value = try require(try self.call_arg(f), "value");
            try f.ir.store(f.curnode, dest, value);
            return true;
        } else if (mem.eql(u8, kw, "xadd")) {
            try self.expect_char('[');
            const dest = try require(try self.call_arg(f), "destination");
            try self.expect_char(']');
            const value = try require(try self.call_arg(f), "value");
            try f.ir.xadd(f.curnode, dest, value);
            return true;
        }
    } else if (try self.varname()) |dest| {
        try self.expect_char('=');
        const item = try nonexisting(&f.refs, dest, "ref %");
        item.* = try self.expr(f);
        return true;
    } else if (try self.labelname()) |label| {
        const item = try f.labels.getOrPut(label);
        if (item.found_existing) {
            if (!f.ir.empty(item.value_ptr.*, false)) {
                print("duplicate label :{s}!\n", .{label});
                return error.ParseError;
            }
        } else {
            item.value_ptr.* = try f.ir.addNode();
        }

        if (f.ir.n.items[f.curnode].s[0] == 0) {
            f.ir.n.items[f.curnode].s[0] = item.value_ptr.*;
        }
        f.curnode = item.value_ptr.*;
        return true;
    }
    return error.ParseError;
}

pub fn call_arg(self: *Self, f: *Func) ParseError!?u16 {
    if (self.num()) |numval| {
        return try f.ir.const_int(f.curnode, @intCast(u16, numval));
    } else if (try self.varname()) |src| {
        return f.refs.get(src) orelse {
            print("undefined ref %{s}!\n", .{src});
            return error.ParseError;
        };
    }
    return null;
}

pub fn expr(self: *Self, f: *Func) ParseError!u16 {
    if (self.num()) |numval| {
        return f.ir.const_int(f.curnode, @intCast(u16, numval));
    } else if (self.keyword()) |kw| {
        if (mem.eql(u8, kw, "call")) {
            const name = try require(self.keyword(), "name");
            const helper = meta.stringToEnum(BPF.Helper, name) orelse {
                print("unknown builtin function: '{s}'\n", .{name});
                return error.ParseError;
            };
            const arg1 = try self.call_arg(f) orelse FLIR.NoRef;
            // hacky hack: if arg1 fails so does arg2
            const arg2 = try self.call_arg(f) orelse FLIR.NoRef;
            const arg3 = try self.call_arg(f) orelse FLIR.NoRef;
            const arg4 = try self.call_arg(f) orelse FLIR.NoRef;
            // TODO: WTF
            if (arg3 != FLIR.NoRef) {
                return f.ir.call4(f.curnode, helper, arg1, arg2, arg3, arg4);
            } else {
                return f.ir.call2(f.curnode, helper, arg1, arg2);
            }
        } else if (mem.eql(u8, kw, "arg")) {
            return f.ir.arg();
        } else if (mem.eql(u8, kw, "alloc")) {
            return f.ir.alloc(f.curnode);
        } else if (mem.eql(u8, kw, "map")) {
            const name = try require(try self.objname(), "map name");
            const map = try self.require_obj(name, .map);
            return f.ir.load_map(f.curnode, @intCast(u64, map.fd), false);
        } else if (mem.eql(u8, kw, "map_value")) {
            const name = try require(try self.objname(), "map name");
            const map = try self.require_obj(name, .map);
            return f.ir.load_map(f.curnode, @intCast(u64, map.fd), true);
        } else if (mem.eql(u8, kw, "ctxreg")) {
            const ctx = try require(try self.call_arg(f), "context");
            _ = self.nonws();
            const reg = try self.identifier();
            const regidx = meta.stringToEnum(bpfUtil.pt_regs_amd64, reg) orelse return error.ParseError;
            const const_off = try f.ir.const_int(f.curnode, 8 * @enumToInt(regidx));
            return f.ir.load(f.curnode, ctx, const_off);
        }
    }
    return error.ParseError;
}
