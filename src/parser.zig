const std = @import("std");
const ParsedArgs = struct {
    input_file: []const u8,
    output_file: []const u8,
};

pub fn parseArgs() !ParsedArgs {
    const args = std.os.argv;
    var result = ParsedArgs{
        .input_file = undefined,
        .output_file = undefined,
    };

    var i: usize = 1; // Start from 1 to skip the program name
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, std.mem.span(args[i]), "--input-file")) {
            if (i + 1 < args.len) {
                result.input_file = std.mem.span(args[i + 1]);
                i += 1; // Skip the next argument as we've consumed it
            } else {
                return error.MissingInputFileValue;
            }
        } else if (std.mem.eql(u8, std.mem.span(args[i]), "--output-file")) {
            if (i + 1 < args.len) {
                result.output_file = std.mem.span(args[i + 1]);
                i += 1; // Skip the next argument as we've consumed it
            } else {
                return error.MissingOutputValue;
            }
        }
    }

    if (result.input_file.len == 0) {
        return error.MissingInputFileValue;
    }

    if (result.output_file.len == 0) {
        return error.MissingOutputFileValue;
    }

    return result;
}

pub fn readFile(buffer: []u8, file_path: []const u8) ![]u8 {
    // Open the file
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const bytes_read = try file.readAll(buffer);
    return buffer[0..bytes_read];
}

pub fn writeAsmToFile(file_path: []const u8, instructions: []const u8) !void {
    const output_file = try std.fs.cwd().createFile(
        file_path,
        .{ .read = true },
    );
    defer (output_file.close());
    try output_file.writeAll("bits 16\n\n");
    try output_file.writeAll(instructions);
}
