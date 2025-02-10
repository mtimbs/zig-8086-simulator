const std = @import("std");
const OperandKind = enum {
    value,
    byte,
    word,
};
const Operand = union(enum) {
    immediate: struct {
        value: u16,
        kind: OperandKind,
    },
    register: []const u8,
    memory: struct {
        kind: OperandKind,
        register: []const u8,
        displacement: ?i16 = null,
    },
};

const BasicInstructionKind = enum { ADD, COMPARE, MOVE, SUBTRACT };
const JumpInstructionKind = enum { JUMP_NOT_ZERO, JUMP_NOT_LESS_THAN, JUMP_NOT_LESS_THAN_OR_EQUAL, JUMP_ON_BELOW, JUMP_ON_BELOW_OR_EQUAL, JUMP_ON_LESS_OR_EQUAL, JUMP_ON_LESS, JUMP_ON_NOT_BELOW, JUMP_ON_NOT_BELOW_OR_EQUAL, JUMP_ON_NOT_OVERFLOW, JUMP_ON_NOT_PAR, JUMP_ON_NOT_SIGN, JUMP_ON_OVERFLOW, JUMP_ON_PARITY, JUMP_ON_SIGN, JUMP_ON_ZERO };

const BasicInstruction = struct {
    kind: BasicInstructionKind,
    destination: Operand,
    source: Operand,
    bytes_consumed: u8,
};
const JumpInstruction = struct {
    kind: JumpInstructionKind,
    relative_bytes: i8,
    bytes_consumed: u8,
};
const Instruction = union(enum) {
    basic: BasicInstruction,
    jump: JumpInstruction,
};

fn handleRegisterMemoryToFromRegister(contents: []const u8, i: u8, kind: BasicInstructionKind) !Instruction {
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
            }
            bytes_consumed += 1;
        },
        .High => {
            if (contents.len < i + 4) {
                return error.InsufficientBytesForDisplacementHigh;
            }
            const d16_value = @as(i16, @bitCast(bytes_to_u16(&[_]u8{ contents[i + 2], contents[i + 3] })));
            if (d16_value != 0) {
                std.log.debug("Displacemnt: {d}", .{d16_value});
                displacement = d16_value;
            }
            bytes_consumed += 2;
        },
    }

    const reg_operand = Operand{ .register = reg };
    const rm_operand = if (mod_bits == 0b11)
        Operand{ .register = rm.register }
    else
        Operand{ .memory = .{
            .kind = .value,
            .register = rm.register,
            .displacement = displacement,
        } };

    return Instruction{ .basic = .{
        .kind = kind,
        .destination = if (d_bit == 0b1) reg_operand else rm_operand,
        .source = if (d_bit == 0b1) rm_operand else reg_operand,
        .bytes_consumed = bytes_consumed,
    } };
}

fn handleImmediateToRegisterMemory(contents: []const u8, i: u8, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const next_byte = contents[i + 1];
    const w_bit = current_byte & 1;
    const s_bit = if (kind == .MOVE) 0 else (current_byte >> 1) & 1;
    const mod_bits = next_byte >> 6;
    const rm_bits = next_byte & ((1 << 3) - 1);
    const rm = try rmDecoder(mod_bits, rm_bits, w_bit);

    std.log.debug("OPCODE: {b}", .{current_byte >> 2});
    std.log.debug("W: {b}", .{w_bit});
    std.log.debug("S: {b}", .{s_bit});
    std.log.debug("MOD: {b}", .{mod_bits});
    std.log.debug("R/M: {b}", .{rm_bits});
    std.log.debug("Register: {s}", .{rm.register});

    var displacement: ?i16 = null;
    var bytes_consumed: u8 = 2; // Default to consuming opcode + mod/rm byte

    switch (rm.displacement) {
        .None => {
            std.log.debug("Displacement: None", .{});
        },
        .Low => {
            std.log.debug("Displacement: Low", .{});
            if (contents.len < i + 3) {
                return error.InsufficientBytesForDisplacementLow;
            }
            const signed_byte = @as(i8, @bitCast(contents[i + 2]));
            const d8_value = @as(i16, signed_byte);
            if (d8_value != 0) {
                displacement = d8_value;
            }
            bytes_consumed += 1;
        },
        .High => {
            std.log.debug("Displacement: High", .{});
            if (contents.len < i + 4) {
                return error.InsufficientBytesForDisplacementHigh;
            }
            const d16_value = @as(i16, @bitCast(bytes_to_u16(&[_]u8{ contents[i + 2], contents[i + 3] })));
            if (d16_value != 0) {
                displacement = d16_value;
            }
            bytes_consumed += 2;
        },
    }

    std.log.debug("Bytes consumed: {d}", .{bytes_consumed});
    std.log.debug("i: {d}", .{i});

    const immediate = if (s_bit == 0b0 and w_bit == 0b1 and contents.len > i + bytes_consumed + 1)
        bytes_to_u16(&[2]u8{ contents[i + bytes_consumed], contents[i + bytes_consumed + 1] })
    else if (w_bit == 0b1 and s_bit == 0b1 and contents.len > i + bytes_consumed)
        bytes_to_u16(&[2]u8{ contents[i + bytes_consumed], 0b0 })
    else if (w_bit == 0b0 and contents.len > i + bytes_consumed)
        bytes_to_u16(&[2]u8{ contents[i + bytes_consumed], 0b0 })
    else
        return error.InsufficientBytesForImmediate;
    // We either consumed 1 or 2 bytes depending on if w was 0 or 1. We do some hackery here because with add/sub etc, the w_bit being 1 actually means there is only a single byte data. It is only
    if (w_bit == 0b1 and s_bit == 1) {
        bytes_consumed += 1;
    } else {
        bytes_consumed += (1 + w_bit);
    }
    std.log.debug("Bytes consumed: {d}", .{bytes_consumed});
    const is_memory = mod_bits != 0b11;
    const rm_operand = if (!is_memory)
        Operand{ .register = rm.register }
    else
        Operand{ .memory = .{
            .kind = getOperandKind(kind, is_memory, w_bit, true),
            .register = rm.register,
            .displacement = displacement,
        } };

    return Instruction{ .basic = .{
        .kind = kind,
        .destination = rm_operand,
        .source = Operand{ .immediate = .{
            .value = immediate,
            .kind = getOperandKind(kind, is_memory, w_bit, false),
        } },
        .bytes_consumed = bytes_consumed,
    } };
}

fn handleImmediateToRegister(contents: []const u8, i: u8, kind: BasicInstructionKind) !Instruction {
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
    return Instruction{
        .basic = .{ .kind = kind, .destination = Operand{ .register = reg }, .source = Operand{ .immediate = .{ .value = immediate, .kind = .value } }, .bytes_consumed = if (w_bit == 0b1) 3 else 2 },
    };
}

fn handleMemoryToAccumulator(contents: []const u8, i: u8, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const w_bit = current_byte & 1;
    const addr_lo = contents[i + 1];
    const addr_hi = contents[i + 2];

    const displacement = @as(i16, @bitCast(bytes_to_u16(&[2]u8{ addr_lo, addr_hi })));
    const reg = regDecoder(0b000, w_bit);

    return Instruction{ .basic = .{ .kind = kind, .destination = Operand{ .register = reg }, .source = Operand{ .memory = .{
        .kind = .value,
        .register = "",
        .displacement = displacement,
    } }, .bytes_consumed = 3 } };
}

fn handleAccumulatorToMemory(contents: []const u8, i: u8, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const w_bit = current_byte & 1;
    const addr_lo = contents[i + 1];
    const addr_hi = contents[i + 2];
    const displacement = @as(i16, @bitCast(bytes_to_u16(&[2]u8{ addr_lo, addr_hi })));
    const reg = regDecoder(0b000, w_bit);

    return Instruction{ .basic = .{ .kind = kind, .destination = Operand{ .memory = .{
        .kind = if (w_bit == 0b0) .byte else .word,
        .register = "",
        .displacement = displacement,
    } }, .source = Operand{ .register = reg }, .bytes_consumed = 3 } };
}

fn handleImmediateToAccumulator(contents: []const u8, i: u8, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const w_bit = current_byte & 1;
    const immediate = bytes_to_u16(&[2]u8{ contents[i + 1], if (w_bit == 0b1) contents[i + 2] else 0b0 });
    const reg = regDecoder(0b000, w_bit);

    return Instruction{ .basic = .{ .kind = kind, .destination = Operand{ .register = reg }, .source = Operand{ .immediate = .{
        .value = immediate,
        .kind = .value,
    } }, .bytes_consumed = 2 + w_bit } };
}

fn handleJump(contents: []const u8, i: u8, kind: JumpInstructionKind) !Instruction {
    // jumps are relative from end of instructions. So we add 2 to the actual value as we need two instructionst encode the jump
    const byte_from_contents: i8 = @bitCast(contents[i + 1]);
    return Instruction{
        .jump = .{ .kind = kind, .relative_bytes = byte_from_contents + 2, .bytes_consumed = 2 },
    };
}

fn getOperandKind(kind: BasicInstructionKind, is_memory: bool, w_bit: u8, is_destination: bool) OperandKind {
    // For register destinations, immediate source should always be .value
    if (!is_memory) return .value;

    if (kind == .MOVE) {
        // For MOV: memory gets .value, immediate gets size
        return if (is_destination) .value else (if (w_bit == 0b0) .byte else .word);
    }
    // For non-MOVE: memory gets size, immediate gets .value
    return if (is_destination) (if (w_bit == 0b0) .byte else .word) else .value;
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
            switch (mem.kind) {
                .byte => try writer.print("byte ", .{}),
                .word => try writer.print("word ", .{}),
                else => {},
            }
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
    switch (instruction) {
        .basic => |basic| {
            const instructionKind = switch (basic.kind) {
                .ADD => "add",
                .COMPARE => "cmp",
                .MOVE => "mov",
                .SUBTRACT => "sub",
            };
            try writer.print("{s} ", .{instructionKind});
            try formatOperand(writer, basic.destination);
            try writer.writeAll(", ");
            try formatOperand(writer, basic.source);
            try writer.writeByte('\n');
        },
        .jump => |jump| {
            switch (jump.kind) {
                .JUMP_NOT_ZERO => try writer.print("jnz", .{}),
                .JUMP_NOT_LESS_THAN => try writer.print("jnl", .{}),
                .JUMP_NOT_LESS_THAN_OR_EQUAL => try writer.print("jnle", .{}),
                .JUMP_ON_BELOW => try writer.print("jb", .{}),
                .JUMP_ON_BELOW_OR_EQUAL => try writer.print("jbe", .{}),
                .JUMP_ON_LESS => try writer.print("jl", .{}),
                .JUMP_ON_LESS_OR_EQUAL => try writer.print("jle", .{}),
                .JUMP_ON_NOT_BELOW => try writer.print("jnb", .{}),
                .JUMP_ON_NOT_BELOW_OR_EQUAL => try writer.print("ja", .{}),
                .JUMP_ON_NOT_OVERFLOW => try writer.print("jno", .{}),
                .JUMP_ON_NOT_PAR => try writer.print("jnp", .{}),
                .JUMP_ON_NOT_SIGN => try writer.print("jns", .{}),
                .JUMP_ON_OVERFLOW => try writer.print("jo", .{}),
                .JUMP_ON_PARITY => try writer.print("jp", .{}),
                .JUMP_ON_SIGN => try writer.print("js", .{}),
                .JUMP_ON_ZERO => try writer.print("jz", .{}),
            }
            if (jump.relative_bytes < 0) {
                try writer.print(" ${d}\n", .{jump.relative_bytes});
            } else {
                try writer.print(" $+{d}\n", .{jump.relative_bytes});
            }
        },
    }
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
            try handleRegisterMemoryToFromRegister(contents, i, .MOVE)
        else if (current_byte >> 1 == 0b1100011)
            try handleImmediateToRegisterMemory(contents, i, .MOVE)
        else if (current_byte >> 4 == 0b1011)
            try handleImmediateToRegister(contents, i, .MOVE)
        else if (current_byte >> 1 == 0b1010000)
            try handleMemoryToAccumulator(contents, i, .MOVE)
        else if (current_byte >> 1 == 0b1010001)
            try handleAccumulatorToMemory(contents, i, .MOVE)
        else if (current_byte >> 2 == 0b0)
            try handleRegisterMemoryToFromRegister(contents, i, .ADD)
        else if (current_byte >> 2 == 0b100000 and (contents[i + 1] >> 3) & 0b111 == 0b000)
            try handleImmediateToRegisterMemory(contents, i, .ADD)
        else if ((current_byte & 0b11111110) == 0b00000100)
            try handleImmediateToAccumulator(contents, i, .ADD)
        else if (current_byte >> 2 == 0b1010)
            try handleRegisterMemoryToFromRegister(contents, i, .SUBTRACT)
        else if (current_byte >> 2 == 0b100000 and (contents[i + 1] >> 3) & 0b111 == 0b101)
            try handleImmediateToRegisterMemory(contents, i, .SUBTRACT)
        else if ((current_byte & 0b11111110) == 0b00101100)
            try handleImmediateToAccumulator(contents, i, .SUBTRACT)
        else if (current_byte >> 2 == 0b001110)
            try handleRegisterMemoryToFromRegister(contents, i, .COMPARE)
        else if (current_byte >> 2 == 0b100000 and (contents[i + 1] >> 3) & 0b111 == 0b111)
            try handleImmediateToRegisterMemory(contents, i, .COMPARE)
        else if ((current_byte & 0b11111110) == 0b00111100)
            try handleImmediateToAccumulator(contents, i, .COMPARE)
        else if (current_byte == 0b01110101)
            try handleJump(contents, i, .JUMP_NOT_ZERO)
        else if (current_byte == 0b01111101)
            try handleJump(contents, i, .JUMP_NOT_LESS_THAN)
        else if (current_byte == 0b01111111)
            try handleJump(contents, i, .JUMP_NOT_LESS_THAN_OR_EQUAL)
        else if (current_byte == 0b01110010)
            try handleJump(contents, i, .JUMP_ON_BELOW)
        else if (current_byte == 0b01110110)
            try handleJump(contents, i, .JUMP_ON_BELOW_OR_EQUAL)
        else if (current_byte == 0b01111100)
            try handleJump(contents, i, .JUMP_ON_LESS)
        else if (current_byte == 0b01111110)
            try handleJump(contents, i, .JUMP_ON_LESS_OR_EQUAL)
        else if (current_byte == 0b01110011)
            try handleJump(contents, i, .JUMP_ON_NOT_BELOW)
        else if (current_byte == 0b01110111)
            try handleJump(contents, i, .JUMP_ON_NOT_BELOW_OR_EQUAL)
        else if (current_byte == 0b01110001)
            try handleJump(contents, i, .JUMP_ON_NOT_OVERFLOW)
        else if (current_byte == 0b01111011)
            try handleJump(contents, i, .JUMP_ON_NOT_PAR)
        else if (current_byte == 0b01111001)
            try handleJump(contents, i, .JUMP_ON_NOT_SIGN)
        else if (current_byte == 0b01110000)
            try handleJump(contents, i, .JUMP_ON_OVERFLOW)
        else if (current_byte == 0b01111010)
            try handleJump(contents, i, .JUMP_ON_PARITY)
        else if (current_byte == 0b01111000)
            try handleJump(contents, i, .JUMP_ON_SIGN)
        else if (current_byte == 0b01110100)
            try handleJump(contents, i, .JUMP_ON_ZERO)
        else {
            i += 1;
            std.log.debug("OPCODE: {b}", .{current_byte});
            continue;
        };

        try formatInstruction(writer, instruction);
        i += switch (instruction) {
            .basic => |basic| basic.bytes_consumed,
            .jump => |jump| jump.bytes_consumed,
        };
    }

    return fbs.getWritten();
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

    // add Register-to-register
    buffer = undefined;
    const bytes_9 = [_]u8{ 0b11, 0b11000 };
    const res_9 = try disassemble(&bytes_9, &buffer);
    try std.testing.expectEqualSlices(u8, "add bx, [bx + si]\n", res_9);

    // add Register-to-register
    buffer = undefined;
    const bytes_10 = [_]u8{ 0b10000011, 0b11000110, 0b10 };
    const res_10 = try disassemble(&bytes_10, &buffer);
    try std.testing.expectEqualSlices(u8, "add si, 2\n", res_10);

    // ADD immediate to accumulator
    buffer = undefined;
    const bytes_11 = [_]u8{ 0b101, 0b11101000, 0b11 };
    const res_11 = try disassemble(&bytes_11, &buffer);
    try std.testing.expectEqualSlices(u8, "add ax, 1000\n", res_11);

    // SUB Register-to-register
    buffer = undefined;
    const bytes_12 = [_]u8{ 0b10000011, 0b11101110, 0b10 };
    const res_12 = try disassemble(&bytes_12, &buffer);
    try std.testing.expectEqualSlices(u8, "sub si, 2\n", res_12);
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
