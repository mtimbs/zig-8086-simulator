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

pub fn readFile(allocator: *const std.mem.Allocator, file_path: []const u8) ![]u8 {
    // Open the file
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    // Get the size of the file
    const file_size = try file.getEndPos();

    // Allocate memory for the file contents
    const buffer = try allocator.alloc(u8, file_size);
    errdefer allocator.free(buffer);

    // Read the entire file into the buffer
    const bytes_read = try file.readAll(buffer);
    if (bytes_read != file_size) {
        // If we didn't read the whole file, return an error
        return error.FileReadError;
    }

    // Return the buffer containing the file contents
    return buffer;
}

pub fn writeAsmToFile(file_path: []const u8, instructions: []u8) !void {
    const output_file = try std.fs.cwd().createFile(
        file_path,
        .{ .read = true },
    );
    defer (output_file.close());
    try output_file.writeAll("bits 16\n\n");
    try output_file.writeAll(instructions);
}
