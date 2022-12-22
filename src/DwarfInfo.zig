debug_info: []const u8,
// debug_abbrev: []const u8,
// debug_str: []const u8,
const std = @import("std");
const print = std.debug.print;

const Self = @This();

pub fn get_dwarf_units(self: Self) !void {
    var it = self.getCompileUnitIterator();
    while (try it.next()) |res| {
        print("ITYM: {}\n", .{res.value});
    }
}

fn getCompileUnitIterator(self: Self) CompileUnitIterator {
    return .{ .ctx = self };
}

// Some pieces taken from https://github.com/kubkon/zig-dwarfdump, with modifications

fn Result(comptime T: type) type {
    return struct { off: usize, value: T };
}

fn result(off: usize, value: anytype) Result(@TypeOf(value)) {
    return .{ .off = off, .value = value };
}

const CompileUnitIterator = struct {
    ctx: Self,
    pos: usize = 0,

    fn next(self: *CompileUnitIterator) !?Result(CompileUnit) {
        if (self.pos >= self.ctx.debug_info.len) return null;

        var stream = std.io.fixedBufferStream(self.ctx.debug_info);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const cuh = try CompileUnit.Header.read(reader);
        const total_length = cuh.length + @as(u64, if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32));

        const cu = CompileUnit{
            .cuh = cuh,
            .debug_info_off = creader.bytes_read,
        };
        const res = result(self.pos, cu);

        self.pos += total_length;

        return res;
    }
};

const CompileUnit = struct {
    cuh: Header,
    debug_info_off: usize,

    const Header = struct {
        is_64bit: bool,
        length: u64,
        version: u16,
        debug_abbrev_offset: u64,
        address_size: u8,

        fn read(reader: anytype) !Header {
            var length: u64 = try reader.readIntLittle(u32);

            const is_64bit = length == 0xffffffff;
            if (is_64bit) {
                length = try reader.readIntLittle(u64);
            }

            const version = try reader.readIntLittle(u16);
            const debug_abbrev_offset = if (is_64bit)
                try reader.readIntLittle(u64)
            else
                try reader.readIntLittle(u32);
            const address_size = try reader.readIntLittle(u8);

            return Header{
                .is_64bit = is_64bit,
                .length = length,
                .version = version,
                .debug_abbrev_offset = debug_abbrev_offset,
                .address_size = address_size,
            };
        }
    };

    inline fn getDebugInfo(self: CompileUnit, ctx: Self) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.cuh.length];
    }

    // fn getAbbrevEntryIterator(self: CompileUnit, ctx: Self) AbbrevEntryIterator {
    //     return .{ .ctx = ctx, .cu = self };
    // }
};
