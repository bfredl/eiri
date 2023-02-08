const std = @import("std");
pub fn build(b: *std.Build) void {
    const opt = b.standardOptimizeOption(.{});
    var exe = b.addExecutable(.{ .name = "eiri", .root_source_file = .{ .path = "src/eiri.zig" }, .optimize = opt });
    exe.install();
}
