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

const ParseError = error{ParseError};
fn require(chunk: ?Chunk, what: []const u8) ParseError!Chunk {
    return chunk orelse {
        print("missing {s}\n", .{what});
        return error.ParseError;
    };
}

pub fn stmt(self: *Self) ParseError!void {
    const kw = self.identifier() orelse return;
    print("keyworda {?s}\n", .{kw});
    if (mem.eql(u8, kw, "map")) {
        const name = try require(self.identifier(), "name");
        const kind = try require(self.identifier(), "kind");
        print("map '{s}' of kind {s}\n", .{ name, kind });
    }
}

pub fn init(str: []const u8) Self {
    return .{ .str = str, .pos = 0 };
}
