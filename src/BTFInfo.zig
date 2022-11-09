const std = @import("std");

const Allocator = std.mem.Allocator;
const File = std.fs.File;

const mem = std.mem;
const os = std.os;
const io = std.io;
const print = std.debug.print;
const BPF = os.linux.BPF;
const btf = BPF.btf;

const Self = @This();
header: btf.Header = undefined,
file_bytes: []align(mem.page_size) const u8 = undefined,

// TODO: unmanage these, you disgust
type_idx2off: std.ArrayListUnmanaged(u32) = undefined,
type_namehash: std.HashMapUnmanaged(u32, u32, DupStringIndexContext, 80) = .{},

pub fn init(btf_file: File) !Self {

    // why mmap gives NODEV :(
    // const file_bytes = try @import("./ElfSymbols.zig").bytemap_ro(btf_file);

    var self = Self{};
    if (try btf_file.read(mem.asBytes(&self.header)) < @sizeOf(@TypeOf(self.header))) {
        return error.Fail;
    }

    print("HEADOFF {}\n", .{self.header});
    const btf_magic = 0xeb9f; // btf.magic is not pub :<
    if (self.header.magic != btf_magic) return error.InvalidMagic;

    const stat = try os.fstat(btf_file.handle);
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;
    const allocator = std.heap.page_allocator;
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);

    try btf_file.seekTo(0);
    if (try btf_file.readAll(buf) < size) {
        return error.IOError;
    }
    self.file_bytes = @alignCast(mem.page_size, buf);
    try self.gettypes(allocator);

    // try self.hgrug();

    return self;
}

comptime {
    if (@sizeOf(btf.Type) != 12) @compileError("btf.Type must be 12 bytes");
}

fn hgrug(self: *Self) !void {
    // TODO: hgrug
    const real_off = self.header.hdr_len + self.header.type_off;
    const type_bytes = self.file_bytes[real_off..][0..self.header.type_len];
    for (self.type_idx2off.items) |pos, t| {
        if (t == 0) continue;
        const hdr = @ptrCast(*const btf.Type, @alignCast(4, type_bytes[pos..]));
        if (hdr.info.kind == .@"struct") {
            const arrpos = pos + @sizeOf(btf.Type);
            const items = nitems(hdr.*);
            print("{}: struct '{s}' w items {}\n", .{ t, self.get_str(hdr.name_off).?, items });
            const arr = @ptrCast([*]const btf.Member, @alignCast(4, type_bytes[arrpos..]))[0..items];
            for (arr) |iytem, i| {
                const toff = if (iytem.typ < self.type_idx2off.items.len) self.type_idx2off.items[iytem.typ] else return error.@"vafan håller du ens på med";
                const typedesc = namm: {
                    if (iytem.typ > 0) {
                        const fieldhdr = @ptrCast(*const btf.Type, @alignCast(4, type_bytes[toff..]));
                        break :namm self.get_str(fieldhdr.name_off).?;
                    } else break :namm "void";
                };

                print("  {}: {s} typ={s} ({}) off={},bs={}\n", .{ i, self.get_str(iytem.name_off).?, typedesc, iytem.typ, iytem.offset.bit, iytem.offset.bitfield_size });
            }
        }
    }
}

pub fn gettypes(self: *Self, allocator: Allocator) !void {
    const real_off = self.header.hdr_len + self.header.type_off;
    const type_bytes = self.file_bytes[real_off..][0..self.header.type_len];
    const max_types = type_bytes.len / @sizeOf(btf.Type);
    print("NYAAA~ {} {} {}\n", .{ max_types, type_bytes.len, @sizeOf(btf.Type) });

    // In practice, max_types is a good guess for the needed capacity
    // Ihe real number of types are roughly max_types/2 for vmlinux.
    self.type_idx2off = try @TypeOf(self.type_idx2off).initCapacity(allocator, max_types);
    self.type_idx2off.appendAssumeCapacity(0); // TODO: how best represent void here?

    const str_bytes = self.file_bytes[self.header.hdr_len + self.header.str_off ..][0..self.header.str_len];
    const ctx: DupStringIndexContext = .{ .bytes = str_bytes };
    try self.type_namehash.ensureTotalCapacityContext(allocator, @intCast(u32, max_types), ctx);

    var pos: u32 = 0;
    var ntypes: usize = 0;
    while (pos + @sizeOf(btf.Type) <= type_bytes.len) {
        const hdr = @ptrCast(*const btf.Type, @alignCast(4, type_bytes[pos..]));
        // print("TYPE {} {s} ", .{ pos, @tagName(hdr.info.kind) });
        // print("NAMM {s}\n", .{self.get_str(hdr.name_off).?});
        const size: usize = the_size: {
            switch (hdr.info.kind) {
                inline else => |t| {
                    const member = member_type(t) orelse return error.InvalidType;
                    // print("type NAMM {s}", .{@typeName(member)});
                    break :the_size @sizeOf(member);
                },
            }
        };
        // print(" SIZE {}, VLEN={}\n", .{ size, hdr.info.vlen });
        const items = nitems(hdr.*);
        self.type_idx2off.appendAssumeCapacity(pos);
        if (str_bytes[hdr.name_off] != 0) {
            const theitem = self.type_namehash.getOrPutAssumeCapacityContext(hdr.name_off, ctx);
            if (theitem.found_existing) {
                print("HUU: {s} {} {}\n", .{ self.get_str(hdr.name_off).?, theitem.value_ptr.*, pos });
                const old_hdr = @ptrCast(*const btf.Type, @alignCast(4, type_bytes[theitem.value_ptr.*..]));
                print("typ {s} vs {s}\n", .{ @tagName(old_hdr.info.kind), @tagName(hdr.info.kind) });
            } else {
                theitem.value_ptr.* = pos; // or index??
            }
        }
        pos += @intCast(u32, @sizeOf(btf.Type) + items * size);
        // if (hdr.info.vlen > 0) os.exit(3);
        ntypes += 1;
    }
    print("NYAAA~~ {} {} fast {}\n", .{ max_types, type_bytes.len, ntypes });
}

fn nitems(hdr: btf.Type) u32 {
    return switch (hdr.info.kind) {
        .@"enum", .enum64, .@"struct", .@"union", .func_proto, .datasec => hdr.info.vlen,
        else => 1, // or zero, but then size is already zero
    };
}

pub fn get_str(self: *Self, off: u32) ?[]const u8 {
    const base_off = self.header.hdr_len + self.header.str_off;
    // TODO: bounds checking
    const str = self.file_bytes[base_off + off ..];
    return mem.sliceTo(str, 0);
}

fn member_type(comptime kind: btf.Kind) ?type {
    return switch (kind) {
        .fwd => void,
        .@"const" => void,
        .@"volatile" => void,
        .restrict => void,
        .ptr => void,
        .typedef => void,
        .func => void,
        .float => void,
        .type_tag => void,
        .int => u32,
        .@"enum" => btf.Enum,
        .enum64 => btf.Enum64,
        .array => btf.Array,
        .@"struct" => btf.Member,
        .@"union" => btf.Member,
        .func_proto => btf.Param,
        .@"var" => btf.Var,
        .datasec => btf.VarSecInfo,
        .decl_tag => btf.DeclTag,
        .unknown => null,
    };
}

// pub fn header(self: *Self) *const BPF.btf.Header {
//    return @ptrCast(*const BPF.btf.Header, self.file_bytes.ptr);
// }

// like StringIndexContext, but buffer could contain duplicate strings?
pub const DupStringIndexContext = struct {
    bytes: []const u8,

    pub fn eql(self: @This(), a: u32, b: u32) bool {
        const a_slice = mem.sliceTo(@ptrCast([*:0]const u8, self.bytes.ptr) + a, 0);
        const b_slice = mem.sliceTo(@ptrCast([*:0]const u8, self.bytes.ptr) + b, 0);
        return mem.eql(u8, a_slice, b_slice);
    }

    pub fn hash(self: @This(), x: u32) u64 {
        const x_slice = mem.sliceTo(@ptrCast([*:0]const u8, self.bytes.ptr) + x, 0);
        return hashString(x_slice);
    }
    fn hashString(s: []const u8) u64 {
        return std.hash.Wyhash.hash(0, s);
    }
};
