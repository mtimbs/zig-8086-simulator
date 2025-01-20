const std = @import("std");
const decoder = @import("decoding.zig");
const parser = @import("parser.zig");

pub fn main() !void {
    // Allocate a fixed amount of data. We're doing 1 MB.
    // We use u8 because 1 byte = 8 bits.
    var fixed_buffer: [1024000]u8 = undefined;
    // Initialize with a FixedBufferAllocator
    var fba = std.heap.FixedBufferAllocator.init(&fixed_buffer);
    // Take the allocator so we can allocate some data
    const fb_allocator = fba.allocator();

    const args = try parser.parseArgs();
    std.log.debug("Parsed Args: \ninput: {s}\noutput: {s}\n", .{ args.input_file, args.output_file });

    // Example usage
    const file_contents = try parser.readFile(&fb_allocator, args.input_file);
    defer fb_allocator.free(file_contents);

    std.log.debug("File contents:\n{b}\n", .{file_contents});
    var buffer: [1024]u8 = undefined;
    const disasembled_asm = try decoder.disassemble(file_contents, &buffer);

    std.log.debug("Output ASM:\n{s}\n", .{disasembled_asm});
    try parser.writeAsmToFile(args.output_file, disasembled_asm);
}
