const Builder = @import("std").build.Builder;
pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    var exe = b.addExecutable("eiri", "src/eiri.zig");
    // exe.addPackagePath("bpf", "libs/bpf/exports.zig");
    exe.setBuildMode(mode);
    // exe.use_stage1 = true;
    exe.install();

    const connect = b.step("connect", "connecto wired");
    const run = exe.run();
    run.step.dependOn(b.getInstallStep());
    connect.dependOn(&run.step);
}
