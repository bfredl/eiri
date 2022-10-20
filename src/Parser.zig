str: []const u8,
pos: usize,

const Self = @This();

const std = @import("std");
const print = std.debug.print;
const mem = std.mem;
const meta = std.meta;

const FLIR = @import("./FLIR.zig");
const BPF = std.os.linux.BPF;

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
fn identifier(self: *Self) ?Chunk {
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

fn varname(self: *Self) ParseError!?Chunk {
    if (self.nonws() != @as(u8, '%')) return null;
    self.pos += 1;
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

fn num(self: *Self) ?i32 {
    const first = self.nonws() orelse return null;
    if (!('0' <= first and first <= '9')) return null;
    var val: i32 = 0;
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

pub fn toplevel(self: *Self, allocator: std.mem.Allocator) ParseError!void {
    const kw = self.identifier() orelse return;
    print("keyworda {?s}\n", .{kw});
    if (mem.eql(u8, kw, "map")) {
        const name = try require(self.identifier(), "name");
        const kind = try require(self.identifier(), "kind");
        const key_size = try require(self.num(), "key_size");
        const val_size = try require(self.num(), "val_size");
        print("map '{s}' of kind {s}, key={}, val={}\n", .{ name, kind, key_size, val_size });
    } else if (mem.eql(u8, kw, "func")) {
        const name = try require(self.identifier(), "name");
        try self.lbrk();
        print("FUNC '{s}' \n", .{name});
        var func: Func = .{
            .ir = try FLIR.init(4, allocator),
            .refs = std.StringHashMap(u16).init(allocator),
        };
        func.curnode = try func.ir.addNode();
        while (true) {
            if (!try self.stmt(&func)) break;
            try self.lbrk();
        }
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
};

pub fn stmt(self: *Self, f: *Func) ParseError!bool {
    if (self.identifier()) |kw| {
        if (mem.eql(u8, kw, "end")) {
            return false;
        } else if (mem.eql(u8, kw, "bar")) {
            return true;
        }
    } else if (try self.varname()) |dest| {
        try self.expect_char('=');
        const item = try f.refs.getOrPut(dest);
        if (item.found_existing) {
            print("duplicate ref %{s}!\n", .{dest});
            return error.ParseError;
        }
        const ref = try self.expr(f);
        print("ASSIGN %{s} to ref {}\n", .{ dest, ref });
        item.value_ptr.* = ref;
        return true;
    }
    return error.ParseError;
}

pub fn expr(self: *Self, f: *Func) ParseError!u16 {
    if (self.num()) |numval| {
        return f.ir.const_int(f.curnode, @intCast(u16, numval));
    } else if (self.identifier()) |kw| {
        if (mem.eql(u8, kw, "call")) {
            const name = try require(self.identifier(), "name");
            const helper = meta.stringToEnum(BPF.Helper, name) orelse {
                print("unknown builtin function: '{s}'\n", .{name});
                return error.ParseError;
            };
            return f.ir.call2(f.curnode, helper, FLIR.NoRef, FLIR.NoRef);
        }
    }
    return error.ParseError;
}

pub fn init(str: []const u8) Self {
    return .{ .str = str, .pos = 0 };
}
