const std = @import("std");

pub fn reg_decoder(reg: u8, w: u8) !*const [2:0]u8 {
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

pub fn rm_decoder(mod: u8, rm: u8, w: u8) !*const [2:0]u8 {
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

test "reg_decoder" {
    var output = try reg_decoder(0b000, 0b1);
    var expected = "ax";
    try std.testing.expectEqualSlices(u8, output, expected);

    output = try reg_decoder(0b000, 0b0);
    expected = "al";
    try std.testing.expectEqualSlices(u8, output, expected);

    output = try reg_decoder(0b001, 0b1);
    expected = "cx";
    try std.testing.expectEqualSlices(u8, output, expected);
}

test "rm_decoder" {
    const mod = 0b11;
    const rm = 0b001;
    const w = 0b1;
    const output = try rm_decoder(mod, rm, w);
    try std.testing.expectEqualSlices(u8, output, "cx");
}
