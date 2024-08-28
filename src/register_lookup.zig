const std = @import("std");

const RegisterFieldEncoding = packed struct(u6) { reg: u4, w: u2 };
const Register = enum(u6) {
    AL = @bitCast(RegisterFieldEncoding{ .reg = 0b000, .w = 0b0 }),
    AX = @bitCast(RegisterFieldEncoding{ .reg = 0b000, .w = 0b1 }),
    CL = @bitCast(RegisterFieldEncoding{ .reg = 0b001, .w = 0b0 }),
    CX = @bitCast(RegisterFieldEncoding{ .reg = 0b001, .w = 0b1 }),
    DL = @bitCast(RegisterFieldEncoding{ .reg = 0b010, .w = 0b0 }),
    DX = @bitCast(RegisterFieldEncoding{ .reg = 0b010, .w = 0b1 }),
    BL = @bitCast(RegisterFieldEncoding{ .reg = 0b011, .w = 0b0 }),
    BX = @bitCast(RegisterFieldEncoding{ .reg = 0b011, .w = 0b1 }),
    AH = @bitCast(RegisterFieldEncoding{ .reg = 0b100, .w = 0b0 }),
    SP = @bitCast(RegisterFieldEncoding{ .reg = 0b100, .w = 0b1 }),
    CH = @bitCast(RegisterFieldEncoding{ .reg = 0b110, .w = 0b0 }),
    BP = @bitCast(RegisterFieldEncoding{ .reg = 0b110, .w = 0b1 }),
    BH = @bitCast(RegisterFieldEncoding{ .reg = 0b111, .w = 0b0 }),
    DI = @bitCast(RegisterFieldEncoding{ .reg = 0b111, .w = 0b1 }),
};
pub fn register_lookup(bits: RegisterFieldEncoding) !*const [2:0]u8 {
    return switch (@as(Register, @enumFromInt(@as(u6, @bitCast(bits))))) {
        .AL => "AL",
        .AX => "AX",
        .CL => "CL",
        .CX => "CX",
        .DL => "DL",
        .DX => "DX",
        .BL => "BL",
        .BX => "BX",
        .AH => "AH",
        .SP => "SP",
        .CH => "CH",
        .BP => "BP",
        .BH => "BH",
        .DI => "DI",
    };
}

test "register_lookup" {
    const output = try register_lookup(.{ .reg = 0b000, .w = 0b1 });
    const expected = "AX";

    try std.testing.expectEqualSlices(u8, output, expected);
}
