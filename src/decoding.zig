const std = @import("std");

pub fn dissassemble(allocator: *const std.mem.Allocator, contents: []u8) ![]u8 {
    var i: u8 = 0;
    // TODO: Use some kind of writer here or something to just do string formatting
    var i_list = std.ArrayList(u8).init(allocator.*);
    const num_bytes = contents.len;
    while (i < num_bytes) : (i += 1) {
        std.log.debug("------------------------------", .{});
        const first_byte = contents[i];
        std.log.debug("byte under inspection: {b}", .{first_byte});

        if (num_bytes < i + 1) {
            // this is just a placeholder until I handle this legitimate case
            // -- at the moment I am only dealing with non-single byte instructions
            return error.OutOfBytesError;
        }

        if (first_byte >> 4 == 0b1011) {
            // This is an Immediate to Register MOV
            const data_one = contents[i + 1];
            const w_bit = (first_byte >> 3) & 1;
            const reg_bits = first_byte & 3;
            std.log.debug("data: {b}", .{data_one});
            std.log.debug("W: {b}", .{w_bit});
            std.log.debug("reg: {b}", .{reg_bits});

            const reg = try regDecoder(reg_bits, w_bit);

            if (w_bit == 0b1 and num_bytes > i + 2) {
                // TODO: somehow convert the [2]u8 to a i16
                const imm_bits = [2]u8{ contents[i + 1], contents[i + 2] };
                const immediate: u16 = std.mem.readInt(u16, &imm_bits, .big);
                std.log.debug("immediate: {d}", .{immediate});
                const instruction = interpolate("mov {s}, {d}\n", .{ reg, immediate });
                try i_list.appendSlice(instruction);
            } else {
                // TODO: somehow convert the [1]u8 to a i16
                const imm_bits = [2]u8{ 0b00000000, contents[i + 1] };
                const immediate: u16 = std.mem.readInt(u16, &imm_bits, .big);
                std.log.debug("immediate: {d}", .{immediate});
                const instruction = interpolate("mov {s}, {d}\n", .{ reg, immediate });
                try i_list.appendSlice(instruction);
            }

            i += (1 + w_bit);
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
            const reg = try regDecoder(reg_bits, w_bit);
            const rm = try rmDecoder(mod_bits, rm_bits, w_bit);

            std.log.debug("Reg: {s}", .{reg});
            std.log.debug("R/M: {s}", .{rm.register});

            const destination = if (d_bit == 0b1) reg else rm.register;
            const source = if (d_bit == 0b0) reg else rm.register;
            const instruction = interpolate("mov {s}, {s}\n", .{ destination, source });
            try i_list.appendSlice(instruction);

            i += 1;
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

fn interpolate(comptime fmt: []const u8, args: anytype) []const u8 {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    writer.print(fmt, args) catch unreachable; // Assuming print won't fail for simplicity
    return fbs.getWritten();
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
