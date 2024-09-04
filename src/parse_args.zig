const std = @import("std");
const ParsedArgs = struct {
    input_file: []const u8,
    output_file: []const u8,
};

pub fn parse_args() !ParsedArgs {
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

    return result;
}
