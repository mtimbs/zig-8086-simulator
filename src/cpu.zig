const std = @import("std");
const decoder = @import("decoding.zig");

const FLAGS = struct {
    const OF: u16 = 1 << 11; // Overflow Flag
    const ZF: u16 = 1 << 6; // Zero Flag
    const SF: u16 = 1 << 7; // Sign Flag
    const CF: u16 = 1 << 0; // Carry Flag
    // ... other flags ...
};

pub const CpuState = struct {
    // Registers
    ax: u16,
    bx: u16,
    cx: u16,
    dx: u16,
    si: u16,
    di: u16,
    bp: u16,
    sp: u16,
    ip: u16, // Instruction Pointer
    flags: u16, // Flags register

    // Memory
    memory: [65536]u8,

    //Instructions
    instructions: std.ArrayList(decoder.Instruction),

    //Other state variables
    halted: bool = false,

    pub fn init(program_data: []const u8) !CpuState {
        var instructions = std.ArrayList(decoder.Instruction).init(std.heap.page_allocator);

        var cpu = CpuState{
            .ax = 0,
            .bx = 0,
            .cx = 0,
            .dx = 0,
            .si = 0,
            .di = 0,
            .bp = 0,
            .sp = 0xFFFE, // Initial stack pointer (example)
            .ip = 0, // Start execution at address 0
            .flags = 0,
            .memory = [_]u8{0} ** 65536,
            .instructions = instructions,
            .halted = false,
        };

        // Copy the program data into the CPU's memory
        @memcpy(cpu.memory[0..program_data.len], program_data);

        // Disassemble the program data.
        var instruction_iterator = decoder.InstructionIterator.init(program_data);

        while (try instruction_iterator.next()) |instruction| {
            try instructions.append(instruction);
        }
        return cpu;
    }

    // Execute a single instruction
    pub fn step(self: *CpuState) !void {
        if (self.halted) return; // Don't execute if halted

        // Fetch the instruction at the current IP
        if (self.ip >= self.instructions.items.len) {
            self.halted = true;
            return;
        }

        const instruction = self.instructions.items[self.ip];

        // Decode and execute the instruction
        switch (instruction) {
            .basic => |basic| {
                try self.executeBasicInstruction(basic);
            },
            .jump => |jump| {
                try self.executeJumpInstruction(jump);
            },
        }

        self.ip += 1; // move to next disassembled line
    }

    // Execute basic type instructions.
    fn executeBasicInstruction(self: *CpuState, instruction: decoder.BasicInstruction) !void {
        const src_val = self.getOperandValue(instruction.source);
        var dest_val = self.getOperandValue(instruction.destination);

        switch (instruction.kind) {
            .ADD => {
                dest_val = (dest_val + src_val) & 0xFFFF; // Basic 16-bit addition with wrapping
                try self.setOperandValue(instruction.destination, dest_val);
            },
            .SUBTRACT => {
                dest_val = (dest_val -% src_val) & 0xFFFF; //wrapping subtract
                try self.setOperandValue(instruction.destination, dest_val);
            },
            .MOVE => {
                try self.setOperandValue(instruction.destination, src_val);
            },
            .COMPARE => {
                const result = (dest_val -% src_val) & 0xFFFF; // Perform subtraction but don't store
                //update flags
                self.setFlags(result, dest_val, src_val, instruction.kind);
            },
        }
        self.setFlags(dest_val, dest_val, src_val, instruction.kind);
    }

    fn setFlags(self: *CpuState, result: u16, dest: u16, src: u16, kind: decoder.BasicInstructionKind) void {
        // Zero Flag (ZF)
        if (result == 0) {
            self.flags |= (1 << 6); // Set ZF (bit 6)
        } else {
            self.flags &= ~FLAGS.ZF; // Clear ZF
        }

        // Sign Flag (SF)
        if ((result >> 15) & 1 == 1) { // Check the most significant bit
            self.flags |= (1 << 7); // Set SF (bit 7)
        } else {
            self.flags &= ~FLAGS.SF; // Clear SF
        }

        // Overflow Flag (OF) - for signed arithmetic
        if (kind == .ADD) {
            // Overflow on addition: if operands have same sign, but result has different sign
            if (((src >> 15) & 1) == ((dest >> 15) & 1) and ((src >> 15) & 1) != ((result >> 15) & 1)) {
                self.flags |= (1 << 11); // Set OF (bit 11)
            } else {
                self.flags &= ~FLAGS.OF;
            }
        } else if (kind == .SUBTRACT) {
            //overflow on subtraction
            //if subtracting two numbers of opposite signs gives a result that matches the sign of the subtrahend, you have an overflow.
            if (((src >> 15) & 1) != ((dest >> 15) & 1) and ((src >> 15) & 1) == ((result >> 15) & 1)) {
                self.flags |= (1 << 11); // Set OF (bit 11)
            } else {
                self.flags &= ~~FLAGS.OF;
            }
        } else {
            self.flags &= ~FLAGS.OF;
        }

        // Carry Flag (CF) - for unsigned arithmetic
        if (kind == .ADD) {
            if (@as(u32, dest) + @as(u32, src) > 0xFFFF) {
                self.flags |= (1 << 0); // Set CF (bit 0)
            } else {
                self.flags &= ~FLAGS.CF; // Clear CF
            }
        } else if (kind == .SUBTRACT) {
            if (dest < src) {
                self.flags |= (1 << 0); // Set CF (bit 0) - borrow occurred
            } else {
                self.flags &= ~FLAGS.CF; // Clear CF
            }
        } else {
            self.flags &= ~FLAGS.CF;
        }

        // TODO: Implement Parity Flag (PF), Auxiliary Carry Flag (AF) - these are less commonly used
    }

    // Execute jump instructions
    fn executeJumpInstruction(self: *CpuState, instruction: decoder.JumpInstruction) !void {
        // Determine if the jump condition is met based on the flags.
        const jump_condition_met: bool = switch (instruction.kind) {
            .JUMP_NOT_ZERO => (self.flags & (1 << 6)) == 0, // ZF = 0
            .JUMP_ON_ZERO => (self.flags & (1 << 6)) != 0, // ZF = 1
            .JUMP_ON_LESS => (self.flags & (1 << 7)) != 0, // SF = 1
            .JUMP_ON_LESS_OR_EQUAL => (self.flags & (1 << 7)) != 0 or (self.flags & (1 << 6)) != 0, // SF = 1 or ZF = 1
            .JUMP_NOT_LESS_THAN => (self.flags & (1 << 7)) == 0,
            .JUMP_NOT_LESS_THAN_OR_EQUAL => (self.flags & (1 << 7)) == 0 and (self.flags & (1 << 6)) == 0, // SF = 0 and ZF = 0
            .JUMP_ON_BELOW => (self.flags & (1 << 0)) != 0, // CF = 1
            .JUMP_ON_BELOW_OR_EQUAL => (self.flags & (1 << 0)) != 0 or (self.flags & (1 << 6)) != 0, // CF = 1 or ZF = 1
            .JUMP_ON_CX_ZERO => self.cx == 0, // CX = 0
            .JUMP_ON_NOT_BELOW => (self.flags & (1 << 0)) == 0, // CF = 0
            .JUMP_ON_NOT_BELOW_OR_EQUAL => (self.flags & (1 << 0)) == 0 and (self.flags & (1 << 6)) == 0, // CF = 0 and ZF = 0
            .JUMP_ON_NOT_OVERFLOW => (self.flags & (1 << 11)) == 0, // OF = 0
            .JUMP_ON_NOT_PAR => (self.flags & (1 << 2)) == 0, // PF = 0
            .JUMP_ON_NOT_SIGN => (self.flags & (1 << 7)) == 0, // SF = 0
            .JUMP_ON_OVERFLOW => (self.flags & (1 << 11)) != 0, // OF = 1
            .JUMP_ON_PARITY => (self.flags & (1 << 2)) != 0, // PF = 1
            .JUMP_ON_SIGN => (self.flags & (1 << 7)) != 0, // SF = 1
            .LOOP_CX_TIMES => blk: {
                self.cx -= 1;
                break :blk self.cx != 0;
            },
            .LOOP_WHILE_NOT_ZERO => blk: {
                self.cx -= 1;
                break :blk self.cx != 0 and (self.flags & (1 << 6)) == 0; // ZF = 0
            },
            .LOOP_WHILE_ZERO => blk: {
                self.cx -= 1;
                break :blk self.cx != 0 and (self.flags & (1 << 6)) != 0; // ZF = 1
            },
        };

        if (jump_condition_met) {
            const current_ip = @as(i16, @intCast(self.ip));
            const new_ip = current_ip +| instruction.relative_bytes -| 1;
            self.ip = @as(u16, @intCast(new_ip));
        }
    }

    // Gets the value of an operand
    fn getOperandValue(self: *CpuState, operand: decoder.Operand) u16 {
        switch (operand) {
            .immediate => |imm| {
                return imm.value;
            },
            .register => |reg| {
                return self.getRegisterValue(reg);
            },
            .memory => |mem| {
                const address = self.calculateEffectiveAddress(operand); // Corrected call
                // Read from memory.  Handle byte/word based on mem.kind.
                return switch (mem.kind) {
                    .byte => self.memory[address],
                    .word, .value => @as(u16, @bitCast(self.memory[address .. address + 2][0..2].*)),
                };
            },
        }
    }

    // Sets the value of an operand
    fn setOperandValue(self: *CpuState, operand: decoder.Operand, value: u16) !void {
        switch (operand) {
            .immediate => {
                // Cannot set the value of an immediate operand.
                return error.InvalidOperand;
            },
            .register => |reg| {
                self.setRegisterValue(reg, value);
            },
            .memory => |mem| {
                const address = self.calculateEffectiveAddress(operand); // Corrected call
                // Write to memory.  Handle byte/word based on mem.kind.
                switch (mem.kind) {
                    .byte => self.memory[address] = @truncate(value), // Truncate to 8 bits
                    .word, .value => std.mem.writeInt(u16, self.memory[address .. address + 2][0..2], value, .little),
                }
            },
        }
    }

    // Gets the value stored in a register
    fn getRegisterValue(self: *CpuState, register_name: []const u8) u16 {
        if (std.mem.eql(u8, register_name, "al")) {
            return @truncate(self.ax & 0xFF);
        } else if (std.mem.eql(u8, register_name, "ax")) {
            return self.ax;
        } else if (std.mem.eql(u8, register_name, "cl")) {
            return @truncate(self.cx & 0xFF);
        } else if (std.mem.eql(u8, register_name, "cx")) {
            return self.cx;
        } else if (std.mem.eql(u8, register_name, "dl")) {
            return @truncate(self.dx & 0xFF);
        } else if (std.mem.eql(u8, register_name, "dx")) {
            return self.dx;
        } else if (std.mem.eql(u8, register_name, "bl")) {
            return @truncate(self.bx & 0xFF);
        } else if (std.mem.eql(u8, register_name, "bx")) {
            return self.bx;
        } else if (std.mem.eql(u8, register_name, "ah")) {
            return @truncate(self.ax >> 8);
        } else if (std.mem.eql(u8, register_name, "ch")) {
            return @truncate(self.cx >> 8);
        } else if (std.mem.eql(u8, register_name, "dh")) {
            return @truncate(self.dx >> 8);
        } else if (std.mem.eql(u8, register_name, "bh")) {
            return @truncate(self.bx >> 8);
        } else if (std.mem.eql(u8, register_name, "sp")) {
            return self.sp;
        } else if (std.mem.eql(u8, register_name, "bp")) {
            return self.bp;
        } else if (std.mem.eql(u8, register_name, "si")) {
            return self.si;
        } else if (std.mem.eql(u8, register_name, "di")) {
            return self.di;
        } else {
            unreachable;
        }
    }

    // Sets the value of a register
    fn setRegisterValue(self: *CpuState, register_name: []const u8, value: u16) void {
        if (std.mem.eql(u8, register_name, "al")) {
            self.ax = (self.ax & 0xFF00) | (@as(u16, @truncate(value)) & 0x00FF);
        } else if (std.mem.eql(u8, register_name, "ax")) {
            self.ax = value;
        } else if (std.mem.eql(u8, register_name, "cl")) {
            self.cx = (self.cx & 0xFF00) | (@as(u16, @truncate(value)) & 0x00FF);
        } else if (std.mem.eql(u8, register_name, "cx")) {
            self.cx = value;
        } else if (std.mem.eql(u8, register_name, "dl")) {
            self.dx = (self.dx & 0xFF00) | (@as(u16, @truncate(value)) & 0x00FF);
        } else if (std.mem.eql(u8, register_name, "dx")) {
            self.dx = value;
        } else if (std.mem.eql(u8, register_name, "bl")) {
            self.bx = (self.bx & 0xFF00) | (@as(u16, @truncate(value)) & 0x00FF);
        } else if (std.mem.eql(u8, register_name, "bx")) {
            self.bx = value;
        } else if (std.mem.eql(u8, register_name, "ah")) {
            self.ax = (self.ax & 0x00FF) | (@as(u16, @truncate(value)) << 8);
        } else if (std.mem.eql(u8, register_name, "ch")) {
            self.cx = (self.cx & 0x00FF) | (@as(u16, @truncate(value)) << 8);
        } else if (std.mem.eql(u8, register_name, "dh")) {
            self.dx = (self.dx & 0x00FF) | (@as(u16, @truncate(value)) << 8);
        } else if (std.mem.eql(u8, register_name, "bh")) {
            self.bx = (self.bx & 0x00FF) | (@as(u16, @truncate(value)) << 8);
        } else if (std.mem.eql(u8, register_name, "sp")) {
            self.sp = value;
        } else if (std.mem.eql(u8, register_name, "bp")) {
            self.bp = value;
        } else if (std.mem.eql(u8, register_name, "si")) {
            self.si = value;
        } else if (std.mem.eql(u8, register_name, "di")) {
            self.di = value;
        } else {
            unreachable;
        }
    }

    // Calculates the effective address for memory operands
    fn calculateEffectiveAddress(self: *CpuState, operand: decoder.Operand) usize {
        switch (operand) {
            .memory => |mem| {
                var addr: usize = switch (mem.register[0]) {
                    'b' => blk2: {
                        if (std.mem.eql(u8, mem.register, "bx + si")) {
                            break :blk2 self.bx +| self.si;
                        } else if (std.mem.eql(u8, mem.register, "bx + di")) {
                            break :blk2 self.bx +| self.di;
                        } else if (std.mem.eql(u8, mem.register, "bp + si")) {
                            break :blk2 self.bp +| self.si;
                        } else if (std.mem.eql(u8, mem.register, "bp + di")) {
                            break :blk2 self.bp +| self.di;
                        } else if (std.mem.eql(u8, mem.register, "bp")) {
                            break :blk2 self.bp;
                        } else if (std.mem.eql(u8, mem.register, "bx")) {
                            break :blk2 self.bx;
                        } else {
                            unreachable;
                        }
                    },
                    's' => blk2: {
                        if (std.mem.eql(u8, mem.register, "si")) {
                            break :blk2 self.si;
                        } else {
                            unreachable;
                        }
                    },
                    'd' => blk2: {
                        if (std.mem.eql(u8, mem.register, "di")) {
                            break :blk2 self.di;
                        } else {
                            unreachable;
                        }
                    },
                    else => 0, // Direct addressing (displacement only)
                };

                if (mem.displacement) |disp| {
                    addr = (@as(usize, @intCast(addr)) +| @as(usize, @intCast(disp))) & 0xFFFF; // Apply displacement
                }

                if (addr >= self.memory.len) {
                    @panic("Address out of bounds");
                }

                return addr;
            },
            else => @panic("calculateEffectiveAddress called with non-memory operand"),
        }
    }

    pub fn getRegisterDisplayStrings(self: *const CpuState) ![][]const u8 {
        var reg_strings = try std.heap.page_allocator.alloc([]const u8, 16);

        reg_strings[0] = try std.fmt.allocPrint(std.heap.page_allocator, "AX: {X:0>4}", .{self.ax});
        reg_strings[1] = try std.fmt.allocPrint(std.heap.page_allocator, "BX: {X:0>4}", .{self.bx});
        reg_strings[2] = try std.fmt.allocPrint(std.heap.page_allocator, "CX: {X:0>4}", .{self.cx});
        reg_strings[3] = try std.fmt.allocPrint(std.heap.page_allocator, "DX: {X:0>4}", .{self.dx});
        reg_strings[4] = try std.fmt.allocPrint(std.heap.page_allocator, "SI: {X:0>4}", .{self.si});
        reg_strings[5] = try std.fmt.allocPrint(std.heap.page_allocator, "DI: {X:0>4}", .{self.di});
        reg_strings[6] = try std.fmt.allocPrint(std.heap.page_allocator, "BP: {X:0>4}", .{self.bp});
        reg_strings[7] = try std.fmt.allocPrint(std.heap.page_allocator, "SP: {X:0>4}", .{self.sp});
        reg_strings[8] = try std.fmt.allocPrint(std.heap.page_allocator, "IP: {X:0>4}", .{self.ip});
        reg_strings[9] = try std.fmt.allocPrint(std.heap.page_allocator, "F:  {X:0>4}", .{self.flags});
        reg_strings[10] = try std.fmt.allocPrint(std.heap.page_allocator, "CF: {d}", .{(self.flags >> 0) & 1}); // Carry Flag
        reg_strings[11] = try std.fmt.allocPrint(std.heap.page_allocator, "PF: {d}", .{(self.flags >> 2) & 1}); // Parity Flag
        reg_strings[12] = try std.fmt.allocPrint(std.heap.page_allocator, "AF: {d}", .{(self.flags >> 4) & 1}); // Auxiliary Carry Flag
        reg_strings[13] = try std.fmt.allocPrint(std.heap.page_allocator, "ZF: {d}", .{(self.flags >> 6) & 1}); // Zero Flag
        reg_strings[14] = try std.fmt.allocPrint(std.heap.page_allocator, "SF: {d}", .{(self.flags >> 7) & 1}); // Sign Flag
        reg_strings[15] = try std.fmt.allocPrint(std.heap.page_allocator, "OF: {d}", .{(self.flags >> 11) & 1}); // Overflow Flag

        return reg_strings;
    }

    pub fn reset(self: *CpuState) void {
        self.ax = 0;
        self.bx = 0;
        self.cx = 0;
        self.dx = 0;
        self.si = 0;
        self.di = 0;
        self.bp = 0;
        self.sp = 0xFFFE;
        self.ip = 0;
        self.flags = 0;
        self.halted = false;
        //You would also want to clear and re-disassemble,
        //but I will handle that when reset is called, in the GUI.
    }
};
