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

const RINGBUF_BUSY_BIT = 1 << 31;
const RINGBUF_DISCARD_BIT = 1 << 30;
const RINGBUF_HDR_SZ = 8;

pub const Sample = struct {
    data: ?[]u8,
    next: usize,
};

pub fn len_roundup(len: c_uint) c_uint {
    const afterlen = (len & ~@as(c_uint, RINGBUF_BUSY_BIT | RINGBUF_DISCARD_BIT)) + RINGBUF_HDR_SZ;
    return (afterlen + 7) & ~@as(c_uint, 7);
}

pub fn peek_event(self: *Self) ?Sample {
    var cons_pos = @atomicLoad(usize, @ptrCast(*usize, self.consumer_blk), .Acquire);
    const prod_pos = @atomicLoad(usize, @ptrCast(*usize, self.producer_blk), .Acquire);
    if (cons_pos < prod_pos) {
        const len_ptr = self.producer_blk[mem.page_size + (cons_pos & self.mask) ..];
        const len = @atomicLoad(c_uint, @ptrCast(*c_uint, @alignCast(@alignOf(c_uint), len_ptr)), .Acquire);
        if (len & RINGBUF_BUSY_BIT != 0) {
            return null;
        }

        const data: ?[]u8 = if (len & RINGBUF_DISCARD_BIT == 0)
            len_ptr[RINGBUF_HDR_SZ..][0..len]
        else
            null;

        return .{ .next = cons_pos + len_roundup(len), .data = data };
    }
    return null;
}

pub fn consume_event(self: *Self, s: Sample) void {
    // TODO: read a batch of events before @atomicStore
    @atomicStore(usize, @ptrCast(*usize, self.consumer_blk), s.next, .Release);
}
