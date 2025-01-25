const std = @import("std");
const decoder = @import("decoding.zig");
const parser = @import("parser.zig");

pub fn main() !void {
    var fixed_buffer: [1024000]u8 = undefined;

    const args = try parser.parseArgs();
    std.log.debug("Parsed Args: \ninput: {s}\noutput: {s}\n", .{ args.input_file, args.output_file });

    const file_contents = try parser.readFile(fixed_buffer[0..512000], args.input_file);

    std.log.debug("File contents:\n{b}\n", .{file_contents});
    const disasembled_asm = try decoder.disassemble(file_contents, fixed_buffer[512000..]);

    std.log.debug("Output ASM:\n{s}\n", .{disasembled_asm});
    try parser.writeAsmToFile(args.output_file, disasembled_asm);
}
