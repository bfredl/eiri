const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const PERF = linux.PERF;
const io = std.io;
const mem = std.mem;
const fd_t = linux.fd_t;
const errno = linux.getErrno;
const p = std.debug.print;

map_fd: fd_t,

const Self = @This();

pub fn init(allocator: mem.Allocator, map_fd: fd_t) !Self {
    _ = allocator;
    return .{ .map_fd = map_fd };
}
