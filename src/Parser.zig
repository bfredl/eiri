str: []const u8,
pos: usize,

fd_objs: std.StringHashMap(i32),
allocator: Allocator,

pub fn init(str: []const u8, allocator: Allocator) Self {
    return .{
        .str = str,
        .pos = 0,
        .fd_objs = std.StringHashMap(i32).init(allocator),
        .allocator = allocator,
    };
}

const Self = @This();

const std = @import("std");
const print = std.debug.print;
const mem = std.mem;
const Allocator = mem.Allocator;
const meta = std.meta;

const FLIR = @import("./FLIR.zig");
const bpfUtil = @import("./bpfUtil.zig");
const BPF = std.os.linux.BPF;
const Codegen = @import("./Codegen.zig");

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
    return ('a' <= c and c <= 'z') or ('0' < c and c < '9') or c == '_';
}

const Chunk = []const u8;
fn keyword(self: *Self) ?Chunk {
    const first = self.nonws() orelse return null;
    if (!('a' <= first and first <= 'z')) return null;
    const start = self.pos;
    while (self.pos < self.str.len) : (self.pos += 1) {
        const next = self.str[self.pos];
        if (!idlike(next)) {
            break;
        }
    }
    return self.str[start..self.pos];
}

fn objname(self: *Self) ParseError!?Chunk {
    if (self.nonws() != @as(u8, '$')) return null;
    self.pos += 1;
    return try self.identifier();
}

fn varname(self: *Self) ParseError!?Chunk {
    if (self.nonws() != @as(u8, '%')) return null;
    self.pos += 1;
    return try self.identifier();
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

const ParseError = error{ ParseError, OutOfMemory };
fn require(val: anytype, what: []const u8) ParseError!@TypeOf(val.?) {
    return val orelse {
        print("missing {s}\n", .{what});
        return error.ParseError;
    };
}

pub fn parse(self: *Self, exec: bool) !void {
    while (self.nonws()) |next| {
        if (next == '\n') {
            self.pos += 1;
            continue;
        }
        try self.toplevel(exec);
    }
}

pub fn toplevel(self: *Self, exec: bool) !void {
    const kw = self.keyword() orelse return;
    if (mem.eql(u8, kw, "map")) {
        const name = try require(try self.objname(), "name");
        const kind = try require(self.keyword(), "kind");
        const key_size = try require(self.num(), "key_size");
        const val_size = try require(self.num(), "val_size");
        const n_entries = try require(self.num(), "n_entries");
        const item = try nonexisting(&self.fd_objs, name, "object $");
        print("map '{s}' of kind {s}, key={}, val={}\n", .{ name, kind, key_size, val_size });
        const map_kind = meta.stringToEnum(BPF.MapType, kind) orelse {
            print("unknown map kind: '{s}'\n", .{kind});
            return error.ParseError;
        };
        const fd = if (exec)
            try BPF.map_create(map_kind, key_size, val_size, n_entries)
        else
            57;
        item.* = fd;
    } else if (mem.eql(u8, kw, "func")) {
        const name = try require(try self.objname(), "name");
        try self.lbrk();
        print("FUNC '{s}' \n", .{name});
        const item = try nonexisting(&self.fd_objs, name, "object $");
        var func: Func = .{
            .ir = try FLIR.init(4, self.allocator),
            .refs = std.StringHashMap(u16).init(self.allocator),
        };
        func.curnode = try func.ir.addNode();
        func.exitnode = try func.ir.addNode();
        while (true) {
            if (!try self.stmt(&func)) break;
            try self.lbrk();
        }
        func.ir.debug_print();
        try func.ir.test_analysis();
        func.ir.debug_print();
        var c = try Codegen.init(self.allocator);
        _ = try Codegen.codegen(&func.ir, &c);
        print("\n", .{});
        c.dump();
        const prog = if (exec) try bpfUtil.prog_load_verbose(.kprobe, c.prog()) else 83;
        item.* = prog;
    } else {
        print("keyworda {?s}\n", .{kw});
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
    exitnode: u16 = FLIR.NoRef,
    refs: std.StringHashMap(u16),
};

fn nonexisting(map: anytype, key: []const u8, what: []const u8) ParseError!@TypeOf(map.getPtr(key).?) {
    const item = try map.getOrPut(key);
    if (item.found_existing) {
        print("duplicate {s}{s}!\n", .{ what, key });
        return error.ParseError;
    }
    return item.value_ptr;
}

pub fn stmt(self: *Self, f: *Func) ParseError!bool {
    if (self.keyword()) |kw| {
        if (mem.eql(u8, kw, "end")) {
            return false;
        } else if (mem.eql(u8, kw, "ret")) {
            if (f.curnode == f.exitnode) {
                print("unreachable exit\n", .{});
                return error.ParseError;
            }
            f.ir.n.items[f.curnode].s[0] = f.exitnode;
            f.curnode = f.exitnode;
            const retval = try require(try self.call_arg(f), "return value");
            try f.ir.ret(f.curnode, retval);
            return true;
        } else if (mem.eql(u8, kw, "eq")) {
            const dest = try require(try self.call_arg(f), "dest");
            const src = try require(try self.call_arg(f), "src");
            try f.ir.icmp(f.curnode, .jeq, dest, src);

            // TODO: infamous interlude
            const newnode = try f.ir.addNode();
            f.ir.n.items[f.curnode].s[0] = newnode;
            f.ir.n.items[f.curnode].s[1] = f.exitnode;
            f.curnode = newnode;
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
        } else if (mem.eql(u8, kw, "alloc")) {
            return f.ir.alloc(f.curnode);
        } else if (mem.eql(u8, kw, "map")) {
            const name = try require(try self.objname(), "map name");
            const map_fd = self.fd_objs.get(name) orelse {
                print("undefined map ${s}!\n", .{name});
                return error.ParseError;
            };
            return f.ir.load_map_fd(f.curnode, @intCast(u64, map_fd));
        }
    }
    return error.ParseError;
}
