const std = @import("std");

pub fn disassemble(allocator: *const std.mem.Allocator, contents: []u8) ![]u8 {
    var i: u8 = 0;
    // TODO: Use some kind of writer here or something to just do string formatting
    var instruction_stack = std.ArrayList(u8).init(allocator.*);
    const num_bytes = contents.len;
    while (i < num_bytes) : (i += 1) {
        std.log.debug("------------------------------", .{});
        const current_byte = contents[i];
        std.log.debug("byte under inspection: {b}", .{current_byte});

        if (num_bytes < i + 1) {
            // this is just a placeholder until I handle this legitimate case
            // -- at the moment I am only dealing with non-single byte instructions
            return error.OutOfBytesError;
        }

        if (current_byte >> 4 == 0b1011) {
            // This is an Immediate to Register MOV
            const data_one = contents[i + 1];
            const w_bit = (current_byte >> 3) & 1;
            const reg_bits = current_byte & ((1 << 3) - 1);
            std.log.debug("data: {b}", .{data_one});
            std.log.debug("W: {b}", .{w_bit});
            std.log.debug("reg: {b}", .{reg_bits});

            const reg = try regDecoder(reg_bits, w_bit);

            if (w_bit == 0b1 and num_bytes >= i + 2) {
                // Convert a [2]u8 to a u16
                const immediate = bytes_to_u16(&[2]u8{ contents[i + 1], contents[i + 2] });
                std.log.debug("immediate: {d}", .{immediate});
                std.log.debug("reg: {s}", .{reg});
                const instruction = try interpolate(allocator, "mov {s}, {d}\n", .{ reg, immediate });
                defer allocator.free(instruction);
                try instruction_stack.appendSlice(instruction);
            } else {
                // To convert to a u16 we need a [2]u8 so we just zero pad to align the bytes
                const immediate = bytes_to_u16(&[2]u8{ contents[i + 1], 0b0 });
                std.log.debug("immediate: {d}", .{immediate});
                std.log.debug("reg: {s}", .{reg});
                const instruction = try interpolate(allocator, "mov {s}, {d}\n", .{ reg, immediate });
                defer allocator.free(instruction);
                std.log.debug("instruction: {s}", .{instruction});
                try instruction_stack.appendSlice(instruction);
            }

            // If the w_bit is 0 we only had a single byte displacement so only need to skip the next byte.
            // If the w_bit is 1 we had a 2 byte displacement so we increment by two.
            // Zig can handle int/binary addition. e.g. 1 + 0b1 is 2.
            i += (1 + w_bit);
        }

        // Register/Memory to/from register
        if (current_byte >> 2 == 0b100010 and num_bytes > i) {
            const next_byte = contents[i + 1];
            const d_bit = current_byte >> 1 & 1;
            const w_bit = current_byte & 1;
            const mod_bits = next_byte >> 6;
            const reg_bits = next_byte >> 3 & ((1 << 3) - 1);
            const rm_bits = next_byte & ((1 << 3) - 1);
            const reg = try regDecoder(reg_bits, w_bit);
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

            const destination = if (d_bit == 0b1) reg else rm.register;
            const source = if (d_bit == 0b0) reg else rm.register;
            if (rm.displacement == .None) {
                // Note: the "[" "]" are not just for len > 2. It represents a dereference of the memory address.
                // This is everything listed in table 4-10 (page 162). Just need a way to include displacement checks
                const instruction = try interpolate(allocator, "mov {s}{s}{s}, {s}{s}{s}\n", .{ if (destination.len > 2) "[" else "", destination, if (destination.len > 2) "]" else "", if (source.len > 2) "[" else "", source, if (source.len > 2) "]" else "" });
                defer allocator.free(instruction);
                try instruction_stack.appendSlice(instruction);
            } else if (rm.displacement == .Low) {
                if (num_bytes >= i + 2) {
                    const d8_value = bytes_to_u16(&[_]u8{ contents[i + 2], 0b0 });
                    if (d8_value == 0) {
                        const instruction = try interpolate(allocator, "mov {s}, [{s}]\n", .{ destination, source });
                        defer allocator.free(instruction);
                        try instruction_stack.appendSlice(instruction);
                    } else {
                        const instruction = try interpolate(allocator, "mov {s}, [{s} + {d}]\n", .{ destination, source, d8_value });
                        defer allocator.free(instruction);
                        try instruction_stack.appendSlice(instruction);
                    }
                } else {
                    return error.InsufficientBytesForDisplacementLow;
                }
            } else {
                if (num_bytes >= i + 3) {
                    const d16_value = bytes_to_u16(&[_]u8{ contents[i + 2], contents[i + 3] });
                    if (d16_value == 0) {
                        const instruction = try interpolate(allocator, "mov {s}, [{s}]\n", .{ destination, source });
                        defer allocator.free(instruction);
                        try instruction_stack.appendSlice(instruction);
                    } else {
                        const instruction = try interpolate(allocator, "mov {s}, [{s} + {d}]\n", .{ destination, source, d16_value });
                        defer allocator.free(instruction);
                        try instruction_stack.appendSlice(instruction);
                    }
                } else {
                    return error.InsufficientBytesForDisplacementHigh;
                }
            }

            i += 1;
        }
    }

    // Return the concatenated string
    return instruction_stack.toOwnedSlice();
}

test "disassemble" {
    // Register-to-register
    const allocator = std.testing.allocator;
    const bytes = [_]u8{ 0b10001001, 0b11011110 };
    const res = try disassemble(&allocator, @constCast(bytes[0..]));
    try std.testing.expectEqualSlices(u8, "mov si, bx\n", res);
    allocator.free(res);

    // 8-bit immediate-to-register (unsigned wrap/overflow)
    const bytes_2 = [_]u8{ 0b10110101, 0b11110100 };
    const res_2 = try disassemble(&allocator, @constCast(bytes_2[0..]));
    try std.testing.expectEqualSlices(u8, "mov ch, 244\n", res_2);
    allocator.free(res_2);

    // 16-bit immediate-to-register (unsigned wrap/overflow)
    const bytes_3 = [_]u8{ 0b10111001, 0b00001100, 0b0000000 };
    const res_3 = try disassemble(&allocator, @constCast(bytes_3[0..]));
    try std.testing.expectEqualSlices(u8, "mov cx, 12\n", res_3);
    allocator.free(res_3);

    // Source address calculation
    const bytes_4 = [_]u8{ 0b10001010, 0b0 };
    const res_4 = try disassemble(&allocator, @constCast(bytes_4[0..]));
    try std.testing.expectEqualSlices(u8, "mov al, [bx + si]\n", res_4);
    allocator.free(res_4);
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

const Displacement = enum { None, Low, High };
const EffectiveAddress = struct { register: []const u8, displacement: Displacement };
fn rmDecoder(mod: u8, rm: u8, w: u8) !EffectiveAddress {
    if (mod == 0b11) {
        const register = try regDecoder(rm, w);
        return EffectiveAddress{ .register = register, .displacement = .None };
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

        return EffectiveAddress{ .register = register, .displacement = displacement };
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

fn interpolate(
    allocator: *const std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) ![]const u8 {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    try writer.print(fmt, args);
    const str = fbs.getWritten();
    const allocated_str = try allocator.alloc(u8, str.len);
    std.mem.copyForwards(u8, allocated_str, str);
    return allocated_str;
}

test "interpolate" {
    const allocator = std.testing.allocator;
    const destination = "cx";
    const source = "bx";
    const str = try interpolate(&allocator, "mov {s}, {s}\n", .{ destination, source });
    defer allocator.free(str);
    try std.testing.expectEqualSlices(u8, str, "mov cx, bx\n");

    const str_2 = try interpolate(&allocator, "mov {s}, {d}\n", .{ "cl", 24 });
    defer allocator.free(str_2);
    try std.testing.expectEqualSlices(u8, str_2, "mov cl, 24\n");
}
