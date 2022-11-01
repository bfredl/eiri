const Builder = @import("std").build.Builder;
pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    var exe = b.addExecutable("eiri", "src/eiri.zig");
    exe.setBuildMode(mode);
    // exe.use_stage1 = true;
    exe.install();
}
