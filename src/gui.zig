const std = @import("std");
const raylib = @import("raylib");
const cpu = @import("cpu.zig");
const decoder = @import("decoding.zig");

pub const App = struct {
    cpu_state: *cpu.CpuState,
    running: bool,
    paused: bool,
    step_requested: bool,
    screen_width: i32,
    screen_height: i32,

    pub fn init(cpu_state: *cpu.CpuState) !App {
        const screen_width = 800;
        const screen_height = 600;

        raylib.initWindow(screen_width, screen_height, "8086 Simulator");
        raylib.setTargetFPS(60); // Set a reasonable frame rate

        return App{
            .cpu_state = cpu_state,
            .running = false,
            .paused = true,
            .step_requested = false,
            .screen_width = screen_width,
            .screen_height = screen_height,
        };
    }

    pub fn run(self: *App) void {
        while (!raylib.windowShouldClose()) {
            self.processInput();
            self.update();
            self.render();
        }
        raylib.closeWindow();
    }

    fn processInput(self: *App) void {
        if (raylib.isKeyPressed(.space)) {
            if (self.paused) {
                self.step_requested = true;
            }
            self.running = true; // Hold down space to run
        }
        if (raylib.isKeyReleased(.space)) {
            self.running = false;
        }

        if (raylib.isKeyPressed(.p)) {
            self.paused = !self.paused;
        }

        //reset key
        if (raylib.isKeyPressed(.r)) {
            //clear old instructions
            self.cpu_state.instructions.clearAndFree();
            //Reset
            self.cpu_state.reset();

            //redisassmble

            var instruction_iterator = decoder.InstructionIterator.init(self.cpu_state.memory[0..]);

            while (true) : (self.cpu_state.ip += 0) {
                const maybe_inst = instruction_iterator.next() catch |err| {
                    std.log.err("Error during instruction iteration: {any}", .{err});
                    break;
                };
                if (maybe_inst) |instruction| {
                    self.cpu_state.instructions.append(instruction) catch |err| {
                        std.log.err("Error appending instruction: {any}", .{err});
                        break; // Stop if we can't append
                    };
                } else {
                    break;
                }
            }
        }
    }

    fn update(self: *App) void {
        if (self.step_requested) {
            if (!self.cpu_state.halted) {
                self.cpu_state.step() catch |err| {
                    std.log.err("Error during step: {any}", .{err}); // Log and continue
                };
            }
            self.step_requested = false;
        }

        if (self.running and !self.cpu_state.halted) {
            self.cpu_state.step() catch |err| {
                std.log.err("Error during run: {any}", .{err});
            }; // Handle potential errors
        }
    }

    fn render(self: *App) void {
        raylib.beginDrawing();
        defer raylib.endDrawing();

        raylib.clearBackground(raylib.Color.white);

        self.renderRegisters();
        self.renderDisassembly();
        self.renderControls();
    }

    fn renderRegisters(self: *App) void {
        const register_strings = self.cpu_state.getRegisterDisplayStrings() catch |err| {
            std.log.err("Error during register string print: {any}", .{err});
            return;
        };
        defer {
            for (register_strings) |str| {
                std.heap.page_allocator.free(str);
            }
            std.heap.page_allocator.free(register_strings);
        }

        var y: i32 = self.screen_height - 20;
        for (register_strings) |reg_str| {
            // Cast to a null-terminated pointer
            const text = @as([*:0]const u8, @ptrCast(reg_str.ptr));
            raylib.drawText(text, 10, y, 20, raylib.Color.black);
            y -= 25;
        }
    }

    fn renderDisassembly(self: *App) void {
        var y: i32 = 20;
        const color = if (self.cpu_state.halted) raylib.Color.red else raylib.Color.black;

        // Display disassembled instructions
        for (self.cpu_state.instructions.items, 0..) |instruction, i| {
            var buffer: [512]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            const writer = stream.writer();

            const address = std.fmt.allocPrintZ(std.heap.page_allocator, "{X:0>4}:    ", .{i}) catch |err| {
                std.log.err("Error during disassembly address print: {any}", .{err});
                return;
            };
            defer std.heap.page_allocator.free(address);
            raylib.drawText(address, 200, y, 20, color);

            decoder.formatInstruction(writer, instruction) catch |err| {
                std.log.err("Error during format instruction print: {any}", .{err});
                return;
            };

            // Handle the allocation error instead of using try
            const instruction_string = std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{stream.getWritten()}) catch |err| {
                std.log.err("Error during instruction string allocation: {any}", .{err});
                return;
            };
            defer std.heap.page_allocator.free(instruction_string);

            // Convert to null-terminated string
            const instruction_string_z = std.heap.page_allocator.dupeZ(u8, instruction_string) catch |err| {
                std.log.err("Error during null-terminated string conversion: {any}", .{err});
                return;
            };
            defer std.heap.page_allocator.free(instruction_string_z);

            if (i == self.cpu_state.ip) {
                raylib.drawText(instruction_string_z, 280, y, 20, raylib.Color.blue);
            } else {
                raylib.drawText(instruction_string_z, 280, y, 20, color);
            }
            y += 25;
        }
    }

    fn renderControls(self: *App) void {
        const controls_text = "[Space] Step/Run, [P] Pause, [R] Reset";
        const text_width = raylib.measureText(controls_text, 16);
        raylib.drawText(controls_text, @divTrunc(self.screen_width - text_width, 2), self.screen_height - 30, 16, raylib.Color.gray);

        const status_message = if (self.cpu_state.halted) "Halted" else if (self.paused) "Paused" else "";
        const status_width = raylib.measureText(status_message, 20);
        const status_color = if (self.cpu_state.halted) raylib.Color.red else raylib.Color.gray;
        raylib.drawText(status_message, @divTrunc(self.screen_width - status_width, 2), 10, 20, status_color);
    }
};
