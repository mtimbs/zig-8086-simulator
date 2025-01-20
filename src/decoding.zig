const std = @import("std");

const Operand = union(enum) {
    immediate: u16,
    register: []const u8,
    memory: struct {
        register: []const u8,
        displacement: ?u16 = null,
    },
};

const Instruction = struct {
    destination: Operand,
    source: Operand,
    bytes_consumed: u8,
};

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
    return Instruction{ .destination = Operand{ .register = reg }, .source = Operand{ .immediate = immediate }, .bytes_consumed = if (w_bit == 0b1) 3 else 2 };
}

fn handleRegisterMemoryToRegister(contents: []const u8, i: u8) !Instruction {
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
    std.log.debug("D: {b}", .{d_bit});
    std.log.debug("W: {b}", .{w_bit});
    std.log.debug("MOD: {b}", .{mod_bits});
    std.log.debug("REG: {b}", .{reg_bits});
    std.log.debug("R/M: {b}", .{rm_bits});
    std.log.debug("REG + W: {b}", .{(reg_bits << 1) + w_bit});
    std.log.debug("Reg: {s}", .{reg});
    std.log.debug("R/M: {s}", .{rm.register});

    var displacement: ?u16 = null;
    var bytes_consumed: u8 = 2; // Default to consuming opcode + mod/rm byte

    switch (rm.displacement) {
        .None => {},
        .Low => {
            if (contents.len < i + 3) {
                return error.InsufficientBytesForDisplacementLow;
            }
            const d8_value = bytes_to_u16(&[_]u8{ contents[i + 2], 0b0 });
            if (d8_value != 0) {
                displacement = d8_value;
                bytes_consumed += 1;
            }
        },
        .High => {
            if (contents.len < i + 4) {
                return error.InsufficientBytesForDisplacementHigh;
            }
            const d16_value = bytes_to_u16(&[_]u8{ contents[i + 2], contents[i + 3] });
            if (d16_value != 0) {
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

fn formatOperand(writer: anytype, operand: Operand) !void {
    switch (operand) {
        .immediate => |imm| try writer.print("{d}", .{imm}),
        .register => |reg| try writer.writeAll(reg),
        .memory => |mem| {
            try writer.writeByte('[');
            try writer.writeAll(mem.register);
            if (mem.displacement) |disp| {
                try writer.print(" + {d}", .{disp});
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
        std.log.debug("------------------------------", .{});
        const current_byte = contents[i];
        std.log.debug("byte under inspection: {b}", .{current_byte});

        if (contents.len < i + 1) {
            // this is just a placeholder until I handle this legitimate case
            // -- at the moment I am only dealing with non-single byte instructions
            return error.OutOfBytesError;
        }

        const instruction = if (current_byte >> 4 == 0b1011)
            try handleImmediateToRegisterMove(contents, i)
        else if (current_byte >> 2 == 0b100010 and contents.len > i)
            try handleRegisterMemoryToRegister(contents, i)
        else {
            i += 1;
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
    const bytes = [_]u8{ 0b10001001, 0b11011110 };
    const res = try disassemble(&bytes, &buffer);
    try std.testing.expectEqualSlices(u8, "mov si, bx\n", res);

    // 8-bit immediate-to-register (unsigned wrap/overflow)
    const bytes_2 = [_]u8{ 0b10110101, 0b11110100 };
    const res_2 = try disassemble(&bytes_2, &buffer);
    try std.testing.expectEqualSlices(u8, "mov ch, 244\n", res_2);

    // 16-bit immediate-to-register (unsigned wrap/overflow)
    const bytes_3 = [_]u8{ 0b10111001, 0b00001100, 0b0000000 };
    const res_3 = try disassemble(&bytes_3, &buffer);
    try std.testing.expectEqualSlices(u8, "mov cx, 12\n", res_3);

    // Source address calculation
    const bytes_4 = [_]u8{ 0b10001010, 0b0 };
    const res_4 = try disassemble(&bytes_4, &buffer);
    try std.testing.expectEqualSlices(u8, "mov al, [bx + si]\n", res_4);

    // destination de-register
    const bytes_5 = [_]u8{ 0b10001000, 0b1101110, 0b0 };
    const res_5 = try disassemble(&bytes_5, &buffer);
    try std.testing.expectEqualSlices(u8, "mov [bp], ch\n", res_5);
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
            0b110 => "bp",
            0b111 => "bx",
            else => error.UnrecognisedRMFieldEncoding,
        };

        const displacement = try switch (mod) {
            0b00 => Displacement.None,
            0b01 => Displacement.Low,
            0b10 => Displacement.High,
            0b11 => Displacement.None,
            else => error.UnrecognisedRegisterFieldEncoding,
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
}
