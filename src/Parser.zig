str: []const u8,
pos: usize,

const Self = @This();

const std = @import("std");
const print = std.debug.print;
const mem = std.mem;

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

const Chunk = []const u8;
fn identifier(self: *Self) ?Chunk {
    const first = self.nonws() orelse return null;
    if (!('a' <= first and first <= 'z')) return null;
    const start = self.pos;
    while (self.pos < self.str.len) : (self.pos += 1) {
        const next = self.str[self.pos];
        if (!('a' <= next and next <= 'z' and !('0' < next and next < '9')) and next != '_') {
            break;
        }
    }
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

const ParseError = error{ParseError};
fn require(val: anytype, what: []const u8) ParseError!@TypeOf(val.?) {
    return val orelse {
        print("missing {s}\n", .{what});
        return error.ParseError;
    };
}

pub fn toplevel(self: *Self) ParseError!void {
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
        while (true) {
            if (!try self.stmt()) break;
            try self.lbrk();
        }
    }
}

pub fn stmt(self: *Self) ParseError!bool {
    const keyword = self.identifier();
    if (keyword) |kw| {
        if (mem.eql(u8, kw, "end")) {
            return false;
        } else if (mem.eql(u8, kw, "bar")) {
            return true;
        }
    }
    return error.ParseError;
}

pub fn init(str: []const u8) Self {
    return .{ .str = str, .pos = 0 };
}
