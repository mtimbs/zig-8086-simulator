const std = @import("std");

const OperandKind = enum {
    value,
    byte,
    word,
};

pub const Operand = union(enum) {
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

pub const BasicInstructionKind = enum { ADD, COMPARE, MOVE, SUBTRACT };
pub const JumpInstructionKind = enum {
    JUMP_NOT_ZERO,
    JUMP_NOT_LESS_THAN,
    JUMP_NOT_LESS_THAN_OR_EQUAL,
    JUMP_ON_BELOW,
    JUMP_ON_BELOW_OR_EQUAL,
    JUMP_ON_CX_ZERO,
    JUMP_ON_LESS_OR_EQUAL,
    JUMP_ON_LESS,
    JUMP_ON_NOT_BELOW,
    JUMP_ON_NOT_BELOW_OR_EQUAL,
    JUMP_ON_NOT_OVERFLOW,
    JUMP_ON_NOT_PAR,
    JUMP_ON_NOT_SIGN,
    JUMP_ON_OVERFLOW,
    JUMP_ON_PARITY,
    JUMP_ON_SIGN,
    JUMP_ON_ZERO,
    LOOP_CX_TIMES,
    LOOP_WHILE_NOT_ZERO,
    LOOP_WHILE_ZERO,
};

pub const BasicInstruction = struct {
    kind: BasicInstructionKind,
    destination: Operand,
    source: Operand,
    bytes_consumed: u8,
};
pub const JumpInstruction = struct {
    kind: JumpInstructionKind,
    relative_bytes: i8,
    bytes_consumed: u8,
};
pub const Instruction = union(enum) {
    basic: BasicInstruction,
    jump: JumpInstruction,
};

fn handleRegisterMemoryToFromRegister(contents: []const u8, i: usize, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const next_byte = contents[i + 1];
    const d_bit = current_byte >> 1 & 1;
    const w_bit = current_byte & 1;
    const mod_bits = next_byte >> 6;
    const reg_bits = next_byte >> 3 & ((1 << 3) - 1);
    const rm_bits = next_byte & ((1 << 3) - 1);
    const reg = regDecoder(reg_bits, w_bit);
    const rm = try rmDecoder(mod_bits, rm_bits, w_bit);

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

fn handleImmediateToRegisterMemory(contents: []const u8, i: usize, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const next_byte = contents[i + 1];
    const w_bit = current_byte & 1;
    const s_bit = if (kind == .MOVE) 0 else (current_byte >> 1) & 1;
    const mod_bits = next_byte >> 6;
    const rm_bits = next_byte & ((1 << 3) - 1);
    const rm = try rmDecoder(mod_bits, rm_bits, w_bit);

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
                displacement = d16_value;
            }
            bytes_consumed += 2;
        },
    }

    const immediate = if (s_bit == 0b0 and w_bit == 0b1 and contents.len > i + bytes_consumed + 1)
        bytes_to_u16(&[2]u8{ contents[i + bytes_consumed], contents[i + bytes_consumed + 1] })
    else if (w_bit == 0b1 and s_bit == 0b1 and contents.len > i + bytes_consumed)
        bytes_to_u16(&[2]u8{ contents[i + bytes_consumed], 0b0 })
    else if (w_bit == 0b0 and contents.len > i + bytes_consumed)
        bytes_to_u16(&[2]u8{ contents[i + bytes_consumed], 0b0 })
    else
        return error.InsufficientBytesForImmediate;

    if (w_bit == 0b1 and s_bit == 1) {
        bytes_consumed += 1;
    } else {
        bytes_consumed += (1 + w_bit);
    }
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

fn handleImmediateToRegister(contents: []const u8, i: usize, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const w_bit = (current_byte >> 3) & 1;
    const reg_bits = current_byte & ((1 << 3) - 1);
    const reg = regDecoder(reg_bits, w_bit);
    const immediate = if (w_bit == 0b1 and contents.len >= i + 2)
        bytes_to_u16(&[2]u8{ contents[i + 1], contents[i + 2] })
    else
        bytes_to_u16(&[2]u8{ contents[i + 1], 0b0 });

    // If the w_bit is 0 we had a 1 byte displacement so we skip next byte (bytes consumed = 2).
    // If the w_bit is 1 we had a 2 byte displacement so we increment by two (bytes_consumed = 3).
    return Instruction{
        .basic = .{ .kind = kind, .destination = Operand{ .register = reg }, .source = Operand{ .immediate = .{ .value = immediate, .kind = .value } }, .bytes_consumed = if (w_bit == 0b1) 3 else 2 },
    };
}

fn handleMemoryToAccumulator(contents: []const u8, i: usize, kind: BasicInstructionKind) !Instruction {
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

fn handleAccumulatorToMemory(contents: []const u8, i: usize, kind: BasicInstructionKind) !Instruction {
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

fn handleImmediateToAccumulator(contents: []const u8, i: usize, kind: BasicInstructionKind) !Instruction {
    const current_byte = contents[i];
    const w_bit = current_byte & 1;
    const immediate = bytes_to_u16(&[2]u8{ contents[i + 1], if (w_bit == 0b1) contents[i + 2] else 0b0 });
    const reg = regDecoder(0b000, w_bit);

    return Instruction{ .basic = .{ .kind = kind, .destination = Operand{ .register = reg }, .source = Operand{ .immediate = .{
        .value = immediate,
        .kind = .value,
    } }, .bytes_consumed = 2 + w_bit } };
}

fn handleJump(contents: []const u8, i: usize, kind: JumpInstructionKind) !Instruction {
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

pub fn formatInstruction(writer: anytype, instruction: Instruction) !void {
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
                .JUMP_ON_CX_ZERO => try writer.print("jcxz", .{}),
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
                .LOOP_CX_TIMES => try writer.print("loop", .{}),
                .LOOP_WHILE_NOT_ZERO => try writer.print("loopnz", .{}),
                .LOOP_WHILE_ZERO => try writer.print("loopz", .{}),
            }
            if (jump.relative_bytes < 0) {
                try writer.print(" ${d}\n", .{jump.relative_bytes});
            } else {
                try writer.print(" $+{d}\n", .{jump.relative_bytes});
            }
        },
    }
}

pub const InstructionIterator = struct {
    bytes: []const u8,
    current_index: usize,

    pub fn init(program_data: []const u8) InstructionIterator {
        return .{
            .bytes = program_data,
            .current_index = 0,
        };
    }

    pub fn next(self: *InstructionIterator) !?Instruction {
        if (self.current_index >= self.bytes.len) {
            return null; // No more instructions
        }

        const current_byte = self.bytes[self.current_index];

        const instruction = if (current_byte >> 2 == 0b100010)
            try handleRegisterMemoryToFromRegister(self.bytes, @intCast(self.current_index), .MOVE)
        else if (current_byte >> 1 == 0b1100011)
            try handleImmediateToRegisterMemory(self.bytes, @intCast(self.current_index), .MOVE)
        else if (current_byte >> 4 == 0b1011)
            try handleImmediateToRegister(self.bytes, @intCast(self.current_index), .MOVE)
        else if (current_byte >> 1 == 0b1010000)
            try handleMemoryToAccumulator(self.bytes, @intCast(self.current_index), .MOVE)
        else if (current_byte >> 1 == 0b1010001)
            try handleAccumulatorToMemory(self.bytes, @intCast(self.current_index), .MOVE)
        else if (current_byte >> 2 == 0b0)
            try handleRegisterMemoryToFromRegister(self.bytes, @intCast(self.current_index), .ADD)
        else if (current_byte >> 2 == 0b100000 and (self.bytes[@intCast(self.current_index + 1)] >> 3) & 0b111 == 0b000)
            try handleImmediateToRegisterMemory(self.bytes, @intCast(self.current_index), .ADD)
        else if ((current_byte & 0b11111110) == 0b00000100)
            try handleImmediateToAccumulator(self.bytes, @intCast(self.current_index), .ADD)
        else if (current_byte >> 2 == 0b1010)
            try handleRegisterMemoryToFromRegister(self.bytes, @intCast(self.current_index), .SUBTRACT)
        else if (current_byte >> 2 == 0b100000 and (self.bytes[@intCast(self.current_index + 1)] >> 3) & 0b111 == 0b101)
            try handleImmediateToRegisterMemory(self.bytes, @intCast(self.current_index), .SUBTRACT)
        else if ((current_byte & 0b11111110) == 0b00101100)
            try handleImmediateToAccumulator(self.bytes, @intCast(self.current_index), .SUBTRACT)
        else if (current_byte >> 2 == 0b001110)
            try handleRegisterMemoryToFromRegister(self.bytes, @intCast(self.current_index), .COMPARE)
        else if (current_byte >> 2 == 0b100000 and (self.bytes[@intCast(self.current_index + 1)] >> 3) & 0b111 == 0b111)
            try handleImmediateToRegisterMemory(self.bytes, @intCast(self.current_index), .COMPARE)
        else if ((current_byte & 0b11111110) == 0b00111100)
            try handleImmediateToAccumulator(self.bytes, @intCast(self.current_index), .COMPARE)
        else if (current_byte == 0b01110101)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_NOT_ZERO)
        else if (current_byte == 0b01111101)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_NOT_LESS_THAN)
        else if (current_byte == 0b01111111)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_NOT_LESS_THAN_OR_EQUAL)
        else if (current_byte == 0b01110010)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_BELOW)
        else if (current_byte == 0b01110110)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_BELOW_OR_EQUAL)
        else if (current_byte == 0b11100011)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_CX_ZERO)
        else if (current_byte == 0b01111100)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_LESS)
        else if (current_byte == 0b01111110)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_LESS_OR_EQUAL)
        else if (current_byte == 0b01110011)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_NOT_BELOW)
        else if (current_byte == 0b01110111)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_NOT_BELOW_OR_EQUAL)
        else if (current_byte == 0b01110001)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_NOT_OVERFLOW)
        else if (current_byte == 0b01111011)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_NOT_PAR)
        else if (current_byte == 0b01111001)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_NOT_SIGN)
        else if (current_byte == 0b01110000)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_OVERFLOW)
        else if (current_byte == 0b01111010)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_PARITY)
        else if (current_byte == 0b01111000)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_SIGN)
        else if (current_byte == 0b01110100)
            try handleJump(self.bytes, @intCast(self.current_index), .JUMP_ON_ZERO)
        else if (current_byte == 0b11100010)
            try handleJump(self.bytes, @intCast(self.current_index), .LOOP_CX_TIMES)
        else if (current_byte == 0b11100000)
            try handleJump(self.bytes, @intCast(self.current_index), .LOOP_WHILE_NOT_ZERO)
        else if (current_byte == 0b11100001)
            try handleJump(self.bytes, @intCast(self.current_index), .LOOP_WHILE_ZERO)
        else {
            self.current_index += 1;
            std.log.debug("OPCODE: {b}", .{current_byte});
            return null; // Skip unrecognized instructions
        };

        self.current_index += switch (instruction) {
            .basic => |basic| basic.bytes_consumed,
            .jump => |jump| jump.bytes_consumed,
        };
        return instruction;
    }
};

//Disassemble function:
pub fn disassemble(program_data: []const u8, writer: anytype) !void {
    var instruction_iterator = InstructionIterator.init(program_data);

    while (try instruction_iterator.next()) |instruction| {
        try formatInstruction(writer, instruction);
    }
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

fn bytes_to_u16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .little);
}
