const std = @import("std");

const Allocator = std.mem.Allocator;
const File = std.fs.File;
const elf = std.elf;
const fs = std.fs;
const io = std.io;
const p = std.debug.print;

// TODO remove this when librarifying
const allocator = std.testing.allocator;

// code based on lib/std/build/InstallRawStep in zig/zig
pub fn get_shstrtab(elf_file: *const File, elf_hdr: elf.Header) !?[]u8 {
    if (elf_hdr.shstrndx >= elf_hdr.shnum) return null;

    var section_headers = elf_hdr.section_header_iterator(elf_file);

    var section_counter: usize = 0;
    while (section_counter < elf_hdr.shstrndx) : (section_counter += 1) {
        _ = (try section_headers.next()).?;
    }

    const shstrtab_shdr = (try section_headers.next()).?;

    const buffer = try allocator.alloc(u8, shstrtab_shdr.sh_size);
    errdefer allocator.free(buffer);

    const num_read = try elf_file.preadAll(buffer, shstrtab_shdr.sh_offset);
    if (num_read != buffer.len) return error.EndOfStream;

    return buffer;
}

pub fn parseElf(elf_file: File) !void {
    const elf_hdr = try std.elf.Header.read(&elf_file);
    p("{}\n", .{elf_hdr});
    const shstrtab = try get_shstrtab(&elf_file, elf_hdr);
    // p("{s}\n", .{shstrtab});

    var section_headers = elf_hdr.section_header_iterator(&elf_file);
    while (try section_headers.next()) |section| {
        const name = if (shstrtab) |s| std.mem.span(@ptrCast([*:0]const u8, &s[section.sh_name])) else "??";
        p("{s}: off {} size {}\n", .{ name, section.sh_offset, section.sh_size });
    }
}

pub fn main() !void {
    const arg = std.mem.span(std.os.argv[1]);
    const fil = try std.fs.cwd().openFile(arg, .{});
    defer fil.close();
    try parseElf(fil);
}
