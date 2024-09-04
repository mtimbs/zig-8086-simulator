const std = @import("std");

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
    std.log.debug("REG + W: {b}", .{(reg_bits << 1) + w_bit});

    // Assume for now only dealing with Register to Register MOV (100010xx)
    var i_list = std.ArrayList(u8).init(allocator.*);

    if (opcode_bits == 0b100010) {
        // MOV [destination], [src]
        try i_list.appendSlice("mov");
        try i_list.appendSlice(" ");
        if (mod_bits == 0b11) {
            const destination = if (d_bit == 0b1) try regDecoder(reg_bits, w_bit) else try rmDecoder(mod_bits, rm_bits, w_bit);
            const source = if (d_bit == 0b0) try regDecoder(reg_bits, w_bit) else try rmDecoder(mod_bits, rm_bits, w_bit);
            try i_list.appendSlice(destination);
            try i_list.appendSlice(", ");
            try i_list.appendSlice(source);
            try i_list.appendSlice("\n");
        }
    } else {
        std.log.err("expected 100010, got {b}", .{first_byte & opcode_bits});
        return error.UnknownOPCode;
    }

    // Return the concatenated string
    return i_list.items;
}

fn regDecoder(reg: u8, w: u8) !*const [2:0]u8 {
    return switch ((reg << 1) + w) {
        0b0000 => "al",
        0b0001 => "ax",
        0b0010 => "cl",
        0b0011 => "cx",
        0b0100 => "dl",
        0b0101 => "dx",
        0b0110 => "bl",
        0b0111 => "bx",
        0b1000 => "ah",
        0b1001 => "sp",
        0b1100 => "ch",
        0b1101 => "bp",
        0b1110 => "bh",
        0b1111 => "di",
        else => error.UnrecognisedRegisterFieldEncoding,
    };
}

fn rmDecoder(mod: u8, rm: u8, w: u8) !*const [2:0]u8 {
    return switch ((mod << 4) + (rm << 1) + w) {
        0b110000 => "al",
        0b110001 => "ax",
        0b110010 => "cl",
        0b110011 => "cx",
        0b110100 => "dl",
        0b110101 => "dx",
        0b110110 => "bl",
        0b110111 => "bx",
        0b111000 => "ah",
        0b111001 => "sp",
        0b111100 => "ch",
        0b111101 => "bp",
        0b111110 => "bh",
        0b111111 => "di",
        else => error.UnrecognisedRegisterMemoryFieldEncoding,
    };
}

test "regDecoder" {
    var output = try regDecoder(0b000, 0b1);
    var expected = "ax";
    try std.testing.expectEqualSlices(u8, output, expected);

    output = try regDecoder(0b000, 0b0);
    expected = "al";
    try std.testing.expectEqualSlices(u8, output, expected);

    output = try regDecoder(0b001, 0b1);
    expected = "cx";
    try std.testing.expectEqualSlices(u8, output, expected);
}

test "rmDecoder" {
    const mod = 0b11;
    const rm = 0b001;
    const w = 0b1;
    const output = try rmDecoder(mod, rm, w);
    try std.testing.expectEqualSlices(u8, output, "cx");
}
