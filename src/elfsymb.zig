const std = @import("std");

const Allocator = std.mem.Allocator;
const File = std.fs.File;
const elf = std.elf;
const mem = std.mem;
const fs = std.fs;
const os = std.os;
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
    const stat = try os.fstat(elf_file.handle);
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    // This one is to read the ELF info. We do more mmapping later
    // corresponding to the actual LOAD sections.
    const file_bytes = try os.mmap(
        null,
        mem.alignForward(size, mem.page_size),
        os.PROT.READ,
        os.MAP.PRIVATE,
        elf_file.handle,
        0,
    );
    defer os.munmap(file_bytes);

    const elf_hdr = try std.elf.Header.read(&elf_file);
    p("{}\n", .{elf_hdr});
    // const shstrtab = try get_shstrtab(&elf_file, elf_hdr);
    // p("{s}\n", .{shstrtab});

    // TODO: can has more than one symtab and shit like that?
    var symtab: ?elf.Elf64_Shdr = null;
    var strtab: ?elf.Elf64_Shdr = null;

    var section_headers = elf_hdr.section_header_iterator(&elf_file);
    while (try section_headers.next()) |section| {
        // const name = if (shstrtab) |s| mem.span(@ptrCast([*:0]const u8, &s[section.sh_name])) else "??";
        // p("{s}: off {} size {} typ {}\n", .{ name, section.sh_offset, section.sh_size, section.sh_type });
        if (section.sh_type == elf.SHT_SYMTAB) {
            symtab = section;
            // TODO: figure out how to actually find the right strtab
        } else if (section.sh_type == elf.SHT_STRTAB and strtab == null) {
            strtab = section;
        }
    }

    if (symtab) |st| {
        p("SYMTAB {}\n", .{st});
        var sym: elf.Elf64_Sym = undefined;
        try elf_file.seekableStream().seekTo(st.sh_offset);
        try elf_file.reader().readNoEof(mem.asBytes(&sym));
        p("SYM0 {}\n", .{sym});
        const x = 200;
        try elf_file.seekableStream().seekTo(st.sh_offset + x * st.sh_entsize);
        try elf_file.reader().readNoEof(mem.asBytes(&sym));
        p("SYM1 {}\n", .{sym});
        if (strtab) |str| {
            var name = mem.sliceTo(file_bytes[str.sh_offset + sym.st_name ..], 0);
            p("NAM1 {s}\n", .{name});
        }
    }
}

pub fn main() !void {
    const arg = mem.span(std.os.argv[1]);
    const fil = try std.fs.cwd().openFile(arg, .{});
    defer fil.close();
    try parseElf(fil);
}
