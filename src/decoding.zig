const std = @import("std");
const Operand = union(enum) {
    immediate: struct {
        value: u16,
        kind: enum {
            value,
            byte,
            word,
        },
    },
    register: []const u8,
    memory: struct {
        register: []const u8,
        displacement: ?i16 = null,
    },
};

const Instruction = struct {
    destination: Operand,
    source: Operand,
    bytes_consumed: u8,
};

fn handleRegisterMemoryToFromRegisterMove(contents: []const u8, i: u8) !Instruction {
    const current_byte = contents[i];
    const next_byte = contents[i + 1];
    const d_bit = current_byte >> 1 & 1;
    const w_bit = current_byte & 1;
    const mod_bits = next_byte >> 6;
    const reg_bits = next_byte >> 3 & ((1 << 3) - 1);
    const rm_bits = next_byte & ((1 << 3) - 1);
    const reg = regDecoder(reg_bits, w_bit);
    const rm = try rmDecoder(mod_bits, rm_bits, w_bit);

    std.log.debug("OPCODE: {b}", .{current_byte >> 2});
    std.log.debug("W: {b}", .{w_bit});
    std.log.debug("D: {b}", .{d_bit});
    std.log.debug("MOD: {b}", .{mod_bits});
    std.log.debug("RM: {b}", .{rm_bits});
    std.log.debug("Reg: {b}", .{reg_bits});
    std.log.debug("Reg: {s}", .{rm.register});

    var displacement: ?i16 = null;
    var bytes_consumed: u8 = 2; // Default to consuming opcode + mod/rm byte

    switch (rm.displacement) {
        .None => {},
        .Low => {
            if (contents.len < i + 3) {
                return error.InsufficientBytesForDisplacementLow;
            }
            const signed_byte = @as(i8, @bitCast(contents[i + 2]));
            const d8_value = @as(i16, signed_byte);
            if (d8_value != 0) {
                displacement = d8_value;
                bytes_consumed += 1;
            }
        },
        .High => {
            if (contents.len < i + 4) {
                return error.InsufficientBytesForDisplacementHigh;
            }
            const d16_value = @as(i16, @bitCast(bytes_to_u16(&[_]u8{ contents[i + 2], contents[i + 3] })));
            if (d16_value != 0) {
                std.log.debug("Displacemnt: {d}", .{d16_value});
                displacement = d16_value;
                bytes_consumed += 2;
            }
        },
    }

    const reg_operand = Operand{ .register = reg };
    const rm_operand = if (mod_bits == 0b11)
        Operand{ .register = rm.register }
    else
        Operand{ .memory = .{
            .register = rm.register,
            .displacement = displacement,
        } };

    return Instruction{
        .destination = if (d_bit == 0b1) reg_operand else rm_operand,
        .source = if (d_bit == 0b1) rm_operand else reg_operand,
        .bytes_consumed = bytes_consumed,
    };
}

fn handleImmediateToRegisterMemoryMove(contents: []const u8, i: u8) !Instruction {
    const current_byte = contents[i];
    const next_byte = contents[i + 1];
    const w_bit = current_byte & 1;
    const mod_bits = next_byte >> 6;
    const rm_bits = next_byte & ((1 << 3) - 1);
    const rm = try rmDecoder(mod_bits, rm_bits, w_bit);

    std.log.debug("OPCODE: {b}", .{current_byte >> 2});
    std.log.debug("W: {b}", .{w_bit});
    std.log.debug("MOD: {b}", .{mod_bits});
    std.log.debug("R/M: {b}", .{rm_bits});
    std.log.debug("R/M: {s}", .{rm.register});

    var displacement: ?i16 = null;
    var bytes_consumed: u8 = 2; // Default to consuming opcode + mod/rm byte

    switch (rm.displacement) {
        .None => {},
        .Low => {
            if (contents.len < i + 3) {
                return error.InsufficientBytesForDisplacementLow;
            }
            const signed_byte = @as(i8, @bitCast(contents[i + 2]));
            const d8_value = @as(i16, signed_byte);
            if (d8_value != 0) {
                displacement = d8_value;
                bytes_consumed += 1;
            }
        },
        .High => {
            if (contents.len < i + 4) {
                return error.InsufficientBytesForDisplacementHigh;
            }
            const d16_value = @as(i16, @bitCast(bytes_to_u16(&[_]u8{ contents[i + 2], contents[i + 3] })));
            if (d16_value != 0) {
                displacement = d16_value;
                bytes_consumed += 2;
            }
        },
    }

    const immediate = if (w_bit == 0b0 and contents.len >= i + bytes_consumed)
        bytes_to_u16(&[2]u8{ contents[bytes_consumed], 0b0 })
    else if (w_bit == 0b1 and contents.len >= i + bytes_consumed + 1)
        bytes_to_u16(&[2]u8{ contents[bytes_consumed], contents[bytes_consumed + 1] })
    else
        return error.InsufficientBytesForImmediate;
    // We either consumed 1 or 2 bytes depending on if w was 0 or 1
    bytes_consumed += (1 + w_bit);

    const rm_operand = if (mod_bits == 0b11)
        Operand{ .register = rm.register }
    else
        Operand{ .memory = .{
            .register = rm.register,
            .displacement = displacement,
        } };

    return Instruction{
        .destination = rm_operand,
        .source = Operand{ .immediate = .{ .value = immediate, .kind = if (w_bit == 0b0) .byte else .word } },
        .bytes_consumed = bytes_consumed,
    };
}

fn handleImmediateToRegisterMove(contents: []const u8, i: u8) !Instruction {
    const current_byte = contents[i];
    const data_one = contents[i + 1];
    const w_bit = (current_byte >> 3) & 1;
    const reg_bits = current_byte & ((1 << 3) - 1);
    std.log.debug("data: {b}", .{data_one});
    std.log.debug("W: {b}", .{w_bit});
    std.log.debug("reg: {b}", .{reg_bits});

    const reg = regDecoder(reg_bits, w_bit);
    const immediate = if (w_bit == 0b1 and contents.len >= i + 2)
        bytes_to_u16(&[2]u8{ contents[i + 1], contents[i + 2] })
    else
        bytes_to_u16(&[2]u8{ contents[i + 1], 0b0 });

    std.log.debug("immediate: {d}", .{immediate});
    std.log.debug("reg: {s}", .{reg});

    // If the w_bit is 0 we had a 1 byte displacement so we skip next byte (bytes consumed = 2).
    // If the w_bit is 1 we had a 2 byte displacement so we increment by two (bytes_consumed = 3).
    return Instruction{ .destination = Operand{ .register = reg }, .source = Operand{ .immediate = .{ .value = immediate, .kind = .value } }, .bytes_consumed = if (w_bit == 0b1) 3 else 2 };
}

fn formatOperand(writer: anytype, operand: Operand) !void {
    switch (operand) {
        .immediate => |imm| {
            switch (imm.kind) {
                .value => try writer.print("{d}", .{imm.value}),
                .byte => try writer.print("byte {d}", .{imm.value}),
                .word => try writer.print("word {d}", .{imm.value}),
            }
        },
        .register => |reg| try writer.writeAll(reg),
        .memory => |mem| {
            try writer.writeByte('[');
            try writer.writeAll(mem.register);
            if (mem.displacement) |disp| {
                if (mem.register.len > 0) {
                    if (disp < 0) {
                        try writer.print(" - {d}", .{-disp});
                    } else if (disp > 0) {
                        try writer.print(" + {d}", .{disp});
                    }
                } else {
                    try writer.print("{d}", .{disp});
                }
            }
            try writer.writeByte(']');
        },
    }
}

fn formatInstruction(writer: anytype, instruction: Instruction) !void {
    try writer.writeAll("mov ");
    try formatOperand(writer, instruction.destination);
    try writer.writeAll(", ");
    try formatOperand(writer, instruction.source);
    try writer.writeByte('\n');
}

// Arguably I could take a writer as an argument here. This would allow me to write directly to
// file or handle larger contents streams. However, I feel like this more 'functional' approach is
// easier for me to reason about. So I will use it for now. I just need to hoist the writer init
// to the call site in order to refactor this
pub fn disassemble(contents: []const u8, buffer: []u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buffer);
    const writer = fbs.writer();

    var i: u8 = 0;
    while (i < contents.len) {
        const current_byte = contents[i];

        if (contents.len < i + 1) {
            // this is just a placeholder until I handle this legitimate case
            // -- at the moment I am only dealing with non-single byte instructions
            return error.OutOfBytesError;
        }

        const instruction = if (current_byte >> 2 == 0b100010 and contents.len > i)
            try handleRegisterMemoryToFromRegisterMove(contents, i)
        else if (current_byte >> 1 == 0b1100011)
            try handleImmediateToRegisterMemoryMove(contents, i)
        else if (current_byte >> 4 == 0b1011)
            try handleImmediateToRegisterMove(contents, i)
        else {
            i += 1;
            std.log.debug("OPCODE: {b}", .{current_byte});
            continue;
        };

        try formatInstruction(writer, instruction);
        i += instruction.bytes_consumed;
    }

    const written = fbs.getWritten();
    std.log.debug("Written content: {s}", .{written});
    return written;
}

test "disassemble" {
    var buffer: [1024]u8 = undefined;

    // Register-to-register
    buffer = undefined;
    const bytes = [_]u8{ 0b10001001, 0b11011110 };
    const res = try disassemble(&bytes, &buffer);
    try std.testing.expectEqualSlices(u8, "mov si, bx\n", res);

    // 8-bit immediate-to-register (unsigned wrap/overflow)
    buffer = undefined;
    const bytes_2 = [_]u8{ 0b10110101, 0b11110100 };
    const res_2 = try disassemble(&bytes_2, &buffer);
    try std.testing.expectEqualSlices(u8, "mov ch, 244\n", res_2);

    // 16-bit immediate-to-register (unsigned wrap/overflow)
    buffer = undefined;
    const bytes_3 = [_]u8{ 0b10111001, 0b00001100, 0b0000000 };
    const res_3 = try disassemble(&bytes_3, &buffer);
    try std.testing.expectEqualSlices(u8, "mov cx, 12\n", res_3);

    // Source address calculation
    buffer = undefined;
    const bytes_4 = [_]u8{ 0b10001010, 0b0 };
    const res_4 = try disassemble(&bytes_4, &buffer);
    try std.testing.expectEqualSlices(u8, "mov al, [bx + si]\n", res_4);

    // destination de-register
    buffer = undefined;
    const bytes_5 = [_]u8{ 0b10001000, 0b1101110, 0b0 };
    const res_5 = try disassemble(&bytes_5, &buffer);
    try std.testing.expectEqualSlices(u8, "mov [bp], ch\n", res_5);

    // signed displacements
    buffer = undefined;
    const bytes_6 = [_]u8{ 0b10001011, 0b1000001, 0b11011011 };
    const res_6 = try disassemble(&bytes_6, &buffer);
    try std.testing.expectEqualSlices(u8, "mov ax, [bx + di - 37]\n", res_6);

    // explicit size, byte
    buffer = undefined;
    const bytes_7 = [_]u8{ 0b11000110, 0b11, 0b111 };
    const res_7 = try disassemble(&bytes_7, &buffer);
    try std.testing.expectEqualSlices(u8, "mov [bp + di], byte 7\n", res_7);

    // direct address
    buffer = undefined;
    const bytes_8 = [_]u8{ 0b10001011, 0b101110, 0b101, 0b0 };
    const res_8 = try disassemble(&bytes_8, &buffer);
    try std.testing.expectEqualSlices(u8, "mov bp, [5]\n", res_8);
}

fn regDecoder(reg: u8, w: u8) []const u8 {
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
        else => unreachable,
    };
}

test "regDecoder" {
    var output = regDecoder(0b000, 0b1);
    var expected = "ax";
    try std.testing.expectEqualSlices(u8, output, expected);

    output = regDecoder(0b000, 0b0);
    expected = "al";
    try std.testing.expectEqualSlices(u8, output, expected);

    output = regDecoder(0b001, 0b1);
    expected = "cx";
    try std.testing.expectEqualSlices(u8, output, expected);
}

const Displacement = enum { None, Low, High };
const EffectiveAddress = struct { register: []const u8, displacement: Displacement, dereference: bool };
fn rmDecoder(mod: u8, rm: u8, w: u8) !EffectiveAddress {
    if (mod == 0b11) {
        return EffectiveAddress{ .register = regDecoder(rm, w), .displacement = .None, .dereference = false };
    } else {
        const register = try switch (rm) {
            0b000 => "bx + si",
            0b001 => "bx + di",
            0b010 => "bp + si",
            0b011 => "bp + di",
            0b100 => "si",
            0b101 => "di",
            0b110 => if (mod == 0b00) "" else "bp",
            0b111 => "bx",
            else => error.UnrecognisedRMFieldEncoding,
        };

        const displacement: Displacement = switch (mod) {
            0b00 => if (rm == 0b110) .High else .None,
            0b01 => .Low,
            0b10 => .High,
            0b11 => .None,
            else => return error.UnrecognisedRegisterFieldEncoding,
        };

        return EffectiveAddress{ .register = register, .displacement = displacement, .dereference = true };
    }

    return error.UnrecognisedRegisterMemoryFieldEncoding;
}

test "rmDecoder" {
    const mod = 0b11;
    const rm = 0b001;
    const w = 0b1;
    const output = try rmDecoder(mod, rm, w);
    try std.testing.expectEqualSlices(u8, output.register, "cx");
}

fn bytes_to_u16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .little);
}

test "bytes_to_u16" {
    try std.testing.expectEqual(12, bytes_to_u16(&[_]u8{ 0b1100, 0b0 }));
    try std.testing.expectEqual(244, bytes_to_u16(&[_]u8{ 0b11110100, 0b0 }));
    try std.testing.expectEqual(3948, bytes_to_u16(&[_]u8{ 0b1101100, 0b1111 }));
    try std.testing.expectEqual(347, bytes_to_u16(&[_]u8{ 0b1011011, 0b1 }));
}
