const std = @import("std");
const os = std.os;
const linux = std.os.linux;
const BPF = linux.BPF;
const PERF = linux.PERF;
const io = std.io;
const mem = std.mem;
const fd_t = linux.fd_t;
const errno = linux.getErrno;
const print = std.debug.print;

map_fd: fd_t,
consumer_blk: []align(mem.page_size) u8 = undefined,
producer_blk: []align(mem.page_size) u8 = undefined,
mask: usize,

const Self = @This();

pub fn init(allocator: mem.Allocator, map_fd: fd_t, max_entries: usize) !Self {
    _ = allocator;
    var self = Self{ .map_fd = map_fd, .mask = max_entries - 1 };

    self.consumer_blk = try std.os.mmap(
        null,
        mem.page_size,
        os.PROT.READ | os.PROT.WRITE,
        os.MAP.SHARED,
        map_fd,
        0,
    );

    self.producer_blk = try std.os.mmap(
        null,
        mem.page_size + 2 * max_entries,
        os.PROT.READ,
        os.MAP.SHARED,
        map_fd,
        mem.page_size,
    );

    return self;
}

pub fn read_event(self: *Self) bool {
    const cons_pos = @atomicLoad(usize, @ptrCast(*usize, self.consumer_blk), .Acquire);
    const prod_pos = @atomicLoad(usize, @ptrCast(*usize, self.producer_blk), .Acquire);
    if (cons_pos < prod_pos) {
        const len_ptr = &self.producer_blk[mem.page_size + (cons_pos & self.mask)];
        const len = @atomicLoad(c_int, @ptrCast(*c_int, @alignCast(@alignOf(c_int), len_ptr)), .Acquire);
        print("lenny {}\n", .{len});
        return true;
    }
    return false;
}
