const std = @import("std");

const Allocator = std.mem.Allocator;
const File = std.fs.File;
const elf = std.elf;
const fs = std.fs;
const io = std.io;
const p = std.debug.print;

pub fn parseElf(file: File) !void {
    const elf_hdr = try std.elf.Header.read(&file);
    p("{}\n", .{elf_hdr});
}

pub fn main() !void {
    const arg = std.mem.span(std.os.argv[1]);
    const fil = try std.fs.cwd().openFile(arg, .{});
    defer fil.close();
    try parseElf(fil);
}
