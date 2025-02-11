const std = @import("std");
const parser = @import("parser.zig");
const cpu = @import("cpu.zig");
const gui = @import("gui.zig");

pub fn main() !void {
    var fixed_buffer: [1024000]u8 = undefined;

    const args = parser.parseArgs() catch |err| return err;
    std.log.debug("Parsed Args: \ninput: {s}\noutput: {s}\n", .{ args.input_file, args.output_file });

    const file_contents = parser.readFile(fixed_buffer[0..512000], args.input_file) catch |err| return err;
    std.log.debug("File contents:\n{b}\n", .{file_contents});

    var cpu_state = cpu.CpuState.init(file_contents) catch |err| return err;

    // Initialize and run the GUI using Clay.
    var app = gui.App.init(&cpu_state) catch |err| return err;
    app.run();
}
