const std = @import("std");

pub fn main() !void {
    // Allocate a fixed amount of data. We're doing 1 MB.
    // We use u8 because 1 byte = 8 bits.
    var buffer: [1024000]u8 = undefined;
    // Initialize with a FixedBufferAllocator
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    // Take the allocator so we can allocate some data
    const allocator = fba.allocator();

    // TODO: Make this file path an input parameter
    var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const path = try std.fs.realpath("./asm_examples/single_register_mov", &path_buffer);

    // Open the file.
    // The `.{}` means use the default version of `File.OpenFlags`.
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    // Read the file
    const file_contents = try file.readToEndAlloc(allocator, 2048);
    defer (allocator.free(file_contents));

    std.log.debug("{b}", .{file_contents});
}
