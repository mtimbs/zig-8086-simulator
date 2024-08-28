const std = @import("std");

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

// We are going to go one opcode at a time and let an method emerge rather than
// trying to solve everything all at once. Starting with register to register MOV
// only. Then will grow from here

// [x, x, x, x, x, x, x] [x, x, x, x, x, x, x, x]
// [OPCODE         D  W] [MOD   REG      R/M    ]
// MOD (MODE):
//      indicates whether on of the operands is in memory or whether both are in registers
//      case: 00
//          memory mode: no displacement*
//      case: 01
//          memory mode: 8-bit displacement
//      case: 10
//          memory mode: 16-bit displacement
//      case: 11
//          register mode: no displacement
// REG (REGISTER):
//      identifies a register than is on of instruction operands.
// R/M (REGISTER/MEMORY):
//      if(MOD=11):
//          second register operant
//      else:
//          how the effective memory address of memory operand is to be calculated
pub fn dissassemble(allocator: *const std.mem.Allocator, contents: []u8) ![]u8 {
    const first_byte = contents[0];
    const second_byte = contents[1];

    const opcode_bits = first_byte >> 2;
    const d_bit = first_byte >> 1 & 1;
    const w_bit = first_byte & 1;
    const mod_bits = second_byte >> 6;
    const reg_bits = second_byte >> 3 & ((1 << 3) - 1);
    const rm_bits = second_byte & ((1 << 3) - 1);
    std.log.debug("OPCODE: {b}", .{opcode_bits});
    std.log.debug("D: {b}", .{d_bit});
    std.log.debug("W: {b}", .{w_bit});
    std.log.debug("MOD: {b}", .{mod_bits});
    std.log.debug("REG: {b}", .{reg_bits});
    std.log.debug("REG check: {}", .{reg_bits == 0b011});
    std.log.debug("R/M: {b}", .{rm_bits});
    std.log.debug("R/M check: {}", .{rm_bits == 0b001});

    // Assume for now only dealing with Register to Register MOV (100010xx)
    var i_list = std.ArrayList(u8).init(allocator.*);

    if (opcode_bits == 0b100010) {
        try i_list.appendSlice("MOV ");
        if (mod_bits == 0b11) {
            try i_list.appendSlice("Ax, ");
            try i_list.appendSlice("Bx");
        }
    } else {
        std.log.err("expected 100010, got {b}", .{first_byte & opcode_bits});
        return error.UnknownOPCode;
    }

    // Return the concatenated string
    return i_list.items;
}

pub fn writeAsmToFile() !void {}

pub fn main() !void {
    // Allocate a fixed amount of data. We're doing 1 MB.
    // We use u8 because 1 byte = 8 bits.
    var fixed_buffer: [1024000]u8 = undefined;
    // Initialize with a FixedBufferAllocator
    var fba = std.heap.FixedBufferAllocator.init(&fixed_buffer);
    // Take the allocator so we can allocate some data
    const allocator = fba.allocator();

    // Example usage
    const file_contents = try readFile(&allocator, "./asm_examples/single_register_mov");
    defer allocator.free(file_contents);

    std.log.debug("File contents:\n{b}\n", .{file_contents});
    const dissasembled_asm = try dissassemble(&allocator, file_contents);
    std.log.debug("Output ASM:\n{s}\n", .{dissasembled_asm});

    // Here is how to write to a file when we have dissasembled code
    // const output_file = try std.fs.cwd().createFile(
    //     "example.asm",
    //     .{ .read = true },
    // );
    // defer (output_file.close());
    // try output_file.writeAll("bits 16\n\n");
    // try output_file.writeAll("mov cx, bx");
}
