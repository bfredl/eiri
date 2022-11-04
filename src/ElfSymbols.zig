const std = @import("std");

const Allocator = std.mem.Allocator;
const File = std.fs.File;
const elf = std.elf;
const mem = std.mem;
const fs = std.fs;
const os = std.os;
const io = std.io;
const print = std.debug.print;
const ArrayList = std.ArrayList;

// code derived on elf handling routines in zig stdlib,
// like build/InstallRawStep.zig and dynamic_library.zig

const Self = @This();

file_bytes: []align(mem.page_size) const u8,
header: elf.Header,
shstrtab: ?[]const u8 = null,
symtab: ?[]const elf.Elf64_Sym = null,
strtab: ?[]const u8 = null,
note_std: ?[]align(4) const u8 = null,

const Stapsdt_hdr = extern struct {
    pc: u64,
    base_adr: u64,
    semaphore: u64,
};

pub const Stapsdt = struct {
    h: Stapsdt_hdr,
    provider: []const u8,
    name: []const u8,
    argdesc: []const u8,
};

pub fn bytemap_ro(file: File) ![]align(mem.page_size) const u8 {
    const stat = try os.fstat(file.handle);
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    return (try os.mmap(
        null,
        mem.alignForward(size, mem.page_size),
        os.PROT.READ,
        os.MAP.PRIVATE,
        file.handle,
        0,
    ))[0..size];
}

pub fn init(elf_file: File) !Self {

    // This one is to read the ELF info. We do more mmapping later
    // corresponding to the actual LOAD sections.
    const file_bytes = try bytemap_ro(elf_file);

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
    var note_sdt: ?elf.Elf64_Shdr = null;
    var section_headers = elf_hdr.section_header_iterator(&stream);
    while (try section_headers.next()) |section| {
        const name = if (self.shstrtab) |s| mem.span(@ptrCast([*:0]const u8, &s[section.sh_name])) else "??";
        if (section.sh_type == elf.SHT_SYMTAB) {
            symtab = section;
            // TODO: figure out how to actually find the right strtab
        } else if (section.sh_type == elf.SHT_STRTAB and strtab == null) {
            strtab = section;
            // TODO: check all notes for NT_STAPSDT, name might not be stable?
        } else if (mem.eql(u8, name, ".note.stapsdt")) {
            note_sdt = section;
        }
    }
    if (symtab) |st| {
        // TODO: 0 + @sizeOf() to avoid compiler bug
        if (st.sh_entsize != 0 + @sizeOf(elf.Elf64_Sym)) return error.Miiii;
        const symtab_raw = file_bytes[st.sh_offset..][0..st.sh_size];
        const items = st.sh_size / st.sh_entsize;
        self.symtab = @ptrCast([*]const elf.Elf64_Sym, @alignCast(8, symtab_raw.ptr))[0..items];
    }

    if (strtab) |st| {
        self.strtab = file_bytes[st.sh_offset..][0..st.sh_size];
    }

    if (note_sdt) |note| {
        self.note_std = @alignCast(4, file_bytes[note.sh_offset..][0..note.sh_size]);
    }

    if (false) {
        var index: usize = 0;
        while (index < 5000) : (index += 1) {
            var sym = self.symtab.?[index];
            // TODO: when is this?
            if (false and sym.st_name > 1 and sym.st_name < self.strtab.?.len) {
                var name = mem.sliceTo(self.strtab.?[sym.st_name - 2 ..], 0);
                print("{s}: {}\n", .{ name, sym.st_size });
            }
        }
    }
    return self;
}

pub fn deinit(self: Self) void {
    os.munmap(self.file_bytes);
}

pub fn get_sdts(self: *const Self, allocator: Allocator) !ArrayList(Stapsdt) {
    var list = ArrayList(Stapsdt).init(allocator);

    const notemem = self.note_std orelse return list;
    var itemmem = notemem[0..];
    // TODO: 0 + @sizeOf() to avoid compiler bug
    const hlen = 0 + @sizeOf(elf.Elf64_Nhdr);
    while (itemmem.len >= hlen) {
        const header = @ptrCast(*const elf.Elf64_Nhdr, itemmem.ptr);
        const notename = itemmem[hlen..][0..header.n_namesz];
        const nlen = mem.alignForward(header.n_namesz, 4);

        _ = notename; // TODO: check name == "stapsdt" ??

        var desc = itemmem[hlen + nlen ..][0..header.n_descsz];
        const dlen = mem.alignForward(header.n_descsz, 4);

        var phdr: Stapsdt_hdr = undefined;
        mem.copy(u8, mem.asBytes(&phdr), desc[0..@sizeOf(Stapsdt_hdr)]);
        const provider = mem.sliceTo(desc[@sizeOf(Stapsdt_hdr)..], 0);
        const namebase = @sizeOf(Stapsdt_hdr) + provider.len + 1;
        const name = mem.sliceTo(desc[namebase..], 0);
        const argdesc = mem.sliceTo(desc[namebase + name.len + 1 ..], 0);
        try list.append(Stapsdt{ .h = phdr, .provider = provider, .name = name, .argdesc = argdesc });

        itemmem = @alignCast(4, itemmem[hlen + nlen + dlen ..]);
    }
    return list;
}
pub fn test_get_usdt(sdts: []Stapsdt, sdtname: []const u8) !Stapsdt {
    for (sdts) |i| {
        // print("IYTEM: {} {s} {s} {s}\n", .{ i.h, i.provider, i.name, i.argdesc });
        if (mem.eql(u8, i.name, sdtname)) {
            return i;
        }
    }
    return error.ProbeNotFound;
}
