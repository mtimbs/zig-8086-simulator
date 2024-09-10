const std = @import("std");

pub fn dissassemble(allocator: *const std.mem.Allocator, contents: []u8) ![]u8 {
    var i: u8 = 0;
    // TODO: Use some kind of writer here or something to just do string formatting
    var i_list = std.ArrayList(u8).init(allocator.*);
    const num_bytes = contents.len;
    while (i < num_bytes) : (i += 1) {
        std.log.debug("------------------------------", .{});
        const first_byte = contents[i];

        if (num_bytes < i + 1) {
            // this is just a placeholder until I handle this legitimate case
            // -- at the moment I am only dealing with non-single byte instructions
            return error.PlaceHolderError;
        }

        if (first_byte >> 4 == 0b1011) {
            // This is an Immediate to Register MOV
            return error.PlaceHolderError;
        }

        // Register/Memory to/from register
        if (first_byte >> 2 == 0b100010) {
            const second_byte = contents[i + 1];
            const d_bit = first_byte >> 1 & 1;
            const w_bit = first_byte & 1;
            const mod_bits = second_byte >> 6;
            const reg_bits = second_byte >> 3 & ((1 << 3) - 1);
            const rm_bits = second_byte & ((1 << 3) - 1);
            std.log.debug("OPCODE: {b}", .{first_byte >> 2});
            std.log.debug("D: {b}", .{d_bit});
            std.log.debug("W: {b}", .{w_bit});
            std.log.debug("MOD: {b}", .{mod_bits});
            std.log.debug("REG: {b}", .{reg_bits});
            std.log.debug("REG check: {}", .{reg_bits == 0b011});
            std.log.debug("R/M: {b}", .{rm_bits});
            std.log.debug("R/M check: {}", .{rm_bits == 0b001});
            std.log.debug("REG + W: {b}", .{(reg_bits << 1) + w_bit});

            // MOV [destination], [src]
            try i_list.appendSlice("mov");
            try i_list.appendSlice(" ");
            const reg = try regDecoder(reg_bits, w_bit);
            const rm = try rmDecoder(mod_bits, rm_bits, w_bit);

            std.log.debug("Reg: {s}", .{reg});
            std.log.debug("R/M: {s}", .{rm.register});

            const destination = if (d_bit == 0b1) reg else rm.register;
            const source = if (d_bit == 0b0) reg else rm.register;
            try i_list.appendSlice(destination);
            try i_list.appendSlice(", ");
            try i_list.appendSlice(source);
            try i_list.appendSlice("\n");
        }
    }

    // Return the concatenated string
    return i_list.items;
}

fn regDecoder(reg: u8, w: u8) ![]const u8 {
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
        0b1010 => "ch",
        0b1011 => "bp",
        0b1100 => "dh",
        0b1101 => "si",
        0b1110 => "bh",
        0b1111 => "di",
        else => error.UnrecognisedRegisterFieldEncoding,
    };
}

const Displacement = enum { None, Low, High };
const EffectiveAddress = struct { register: []const u8, displacement: Displacement };
fn rmDecoder(mod: u8, rm: u8, w: u8) !EffectiveAddress {
    if (mod == 0b11) {
        const register = try regDecoder(rm, w);
        return EffectiveAddress{ .register = register, .displacement = .None };
    } else {
        const register = try switch (rm << 1) {
            0b000 => "[bx + si]",
            0b001 => "[bx + di]",
            0b010 => "[bp + si]",
            0b011 => "[bp + di]",
            0b100 => "si",
            0b101 => "di",
            0b110 => "bp",
            0b111 => "bx",
            else => error.UnrecognisedRegisterFieldEncoding,
        };

        const displacement = try switch (mod) {
            0b00 => Displacement.None,
            0b01 => Displacement.Low,
            0b10 => Displacement.High,
            0b11 => Displacement.None,
            else => error.UnrecognisedRegisterFieldEncoding,
        };

        return EffectiveAddress{ .register = register, .displacement = displacement };
    }

    return error.UnrecognisedRegisterMemoryFieldEncoding;
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
    try std.testing.expectEqualSlices(u8, output.register, "cx");
}
