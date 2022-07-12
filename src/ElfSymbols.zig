const std = @import("std");

const Allocator = std.mem.Allocator;
const File = std.fs.File;
const elf = std.elf;
const mem = std.mem;
const fs = std.fs;
const os = std.os;
const io = std.io;
const p = std.debug.print;

// code derived on elf handling routines in zig stdlib,
// like build/InstallRawStep.zig and dynamic_library.zig

const Self = @This();

file_bytes: []align(mem.page_size) u8,
header: elf.Header,
shstrtab: ?[]u8 = null,
symtab: ?[]elf.Elf64_Sym = null,
strtab: ?[]u8 = null,

pub fn init(elf_file: File) !Self {
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
    const elf_hdr = try std.elf.Header.parse(file_bytes[0..64]);
    var stream = io.fixedBufferStream(file_bytes);

    var self = Self{ .file_bytes = file_bytes, .header = elf_hdr };

    if (elf_hdr.shstrndx < elf_hdr.shnum) {
        var section_headers = elf_hdr.section_header_iterator(&stream);

        var section_counter: usize = 0;
        while (section_counter < elf_hdr.shstrndx) : (section_counter += 1) {
            _ = (try section_headers.next()).?;
        }
        const shstrtab_shdr = (try section_headers.next()).?;
        self.shstrtab = file_bytes[shstrtab_shdr.sh_offset..][0..shstrtab_shdr.sh_size];
    }

    var symtab: ?elf.Elf64_Shdr = null;
    var strtab: ?elf.Elf64_Shdr = null;
    var section_headers = elf_hdr.section_header_iterator(&stream);
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
        if (st.sh_entsize != @sizeOf(elf.Elf64_Sym)) return error.Miiii;
        const symtab_raw = file_bytes[st.sh_offset..][0..st.sh_size];
        const items = st.sh_size / st.sh_entsize;
        self.symtab = @ptrCast([*]elf.Elf64_Sym, symtab_raw.ptr)[0..items];
    }

    if (strtab) |st| {
        self.strtab = file_bytes[st.sh_offset..][0..st.sh_size];
    }
    return self;
}

pub fn deinit(self: Self) void {
    os.munmap(self.file_bytes);
}

pub fn main() !void {
    const arg = mem.span(std.os.argv[1]);
    const self = try init(try std.fs.cwd().openFile(arg, .{}));

    var index: usize = 0;
    while (index < 5000) : (index += 1) {
        var sym = self.symtab.?[index];
        // TODO: when is this?
        if (sym.st_name > 1 and sym.st_name < self.strtab.?.len) {
            var name = mem.sliceTo(self.strtab.?[sym.st_name - 2 ..], 0);
            p("{s}: {}\n", .{ name, sym.st_size });
        }
    }
    defer self.deinit();
}
