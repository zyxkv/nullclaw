//! Tools module — agent tool integrations for LLM function calling.
//!
//! Provides a common Tool vtable, ToolResult/ToolSpec types, and implementations
//! for shell execution, file I/O, HTTP requests, git operations, memory tools,
//! scheduling, delegation, browser, and image tools.

const std = @import("std");

// Sub-modules
pub const shell = @import("shell.zig");
pub const file_read = @import("file_read.zig");
pub const file_write = @import("file_write.zig");
pub const file_edit = @import("file_edit.zig");
pub const http_request = @import("http_request.zig");
pub const git = @import("git.zig");
pub const memory_store = @import("memory_store.zig");
pub const memory_recall = @import("memory_recall.zig");
pub const memory_forget = @import("memory_forget.zig");
pub const schedule = @import("schedule.zig");
pub const delegate = @import("delegate.zig");
pub const browser = @import("browser.zig");
pub const image = @import("image.zig");
pub const composio = @import("composio.zig");
pub const screenshot = @import("screenshot.zig");
pub const browser_open = @import("browser_open.zig");
pub const hardware_info = @import("hardware_info.zig");
pub const hardware_memory = @import("hardware_memory.zig");
pub const cron_add = @import("cron_add.zig");
pub const cron_list = @import("cron_list.zig");
pub const cron_remove = @import("cron_remove.zig");
pub const cron_runs = @import("cron_runs.zig");
pub const cron_run = @import("cron_run.zig");
pub const cron_update = @import("cron_update.zig");
pub const message = @import("message.zig");
pub const pushover = @import("pushover.zig");
pub const schema = @import("schema.zig");
pub const web_search = @import("web_search.zig");
pub const web_fetch = @import("web_fetch.zig");
pub const file_append = @import("file_append.zig");
pub const spawn = @import("spawn.zig");
pub const i2c = @import("i2c.zig");
pub const spi = @import("spi.zig");

// ── Core types ──────────────────────────────────────────────────────

/// Result of a tool execution
pub const ToolResult = struct {
    success: bool,
    output: []const u8,
    error_msg: ?[]const u8 = null,

    /// Create a success result
    pub fn ok(output: []const u8) ToolResult {
        return .{ .success = true, .output = output };
    }

    /// Create a failure result
    pub fn fail(err: []const u8) ToolResult {
        return .{ .success = false, .output = "", .error_msg = err };
    }
};

/// Description of a tool for the LLM (function calling schema)
pub const ToolSpec = struct {
    name: []const u8,
    description: []const u8,
    parameters_json: []const u8,
};

/// Tool vtable — implement for any capability.
/// Uses Zig's type-erased interface pattern.
pub const Tool = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        execute: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult,
        name: *const fn (ptr: *anyopaque) []const u8,
        description: *const fn (ptr: *anyopaque) []const u8,
        parameters_json: *const fn (ptr: *anyopaque) []const u8,
    };

    pub fn execute(self: Tool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        return self.vtable.execute(self.ptr, allocator, args_json);
    }

    pub fn name(self: Tool) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn description(self: Tool) []const u8 {
        return self.vtable.description(self.ptr);
    }

    pub fn parametersJson(self: Tool) []const u8 {
        return self.vtable.parameters_json(self.ptr);
    }

    pub fn spec(self: Tool) ToolSpec {
        return .{
            .name = self.name(),
            .description = self.description(),
            .parameters_json = self.parametersJson(),
        };
    }
};

/// Create the default tool set (shell, file_read, file_write).
pub fn defaultTools(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
) ![]Tool {
    var list: std.ArrayList(Tool) = .{};
    errdefer list.deinit(allocator);

    // NOTE: Tool structs are heap-allocated to ensure they outlive the function scope.
    // These allocations are not freed here - they live for the program duration.
    // The caller is responsible for cleanup if needed.

    const st = try allocator.create(shell.ShellTool);
    st.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, wt.tool());

    const et = try allocator.create(file_edit.FileEditTool);
    et.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, et.tool());

    return list.toOwnedSlice(allocator);
}

/// Create all tools including optional ones.
pub fn allTools(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    opts: struct {
        http_enabled: bool = false,
        browser_enabled: bool = false,
        screenshot_enabled: bool = false,
        composio_api_key: ?[]const u8 = null,
        browser_open_domains: ?[]const []const u8 = null,
        hardware_boards: ?[]const []const u8 = null,
        mcp_tools: ?[]const Tool = null,
        agents: ?[]const @import("../config.zig").NamedAgentConfig = null,
        fallback_api_key: ?[]const u8 = null,
        delegate_depth: u32 = 0,
        subagent_manager: ?*@import("../subagent.zig").SubagentManager = null,
    },
) ![]Tool {
    var list: std.ArrayList(Tool) = .{};
    errdefer list.deinit(allocator);

    // NOTE: Tool structs are heap-allocated to ensure they outlive the function scope.
    // These allocations are not freed here - they live for the program duration.
    // The caller is responsible for cleanup if needed.

    // Core tools with workspace_dir
    const st = try allocator.create(shell.ShellTool);
    st.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, wt.tool());

    const et2 = try allocator.create(file_edit.FileEditTool);
    et2.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, et2.tool());

    const gt = try allocator.create(git.GitTool);
    gt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, gt.tool());

    // Tools without workspace_dir
    const it = try allocator.create(image.ImageInfoTool);
    it.* = .{};
    try list.append(allocator, it.tool());

    // Memory tools (work gracefully without a backend)
    const mst = try allocator.create(memory_store.MemoryStoreTool);
    mst.* = .{};
    try list.append(allocator, mst.tool());

    const mrt = try allocator.create(memory_recall.MemoryRecallTool);
    mrt.* = .{};
    try list.append(allocator, mrt.tool());

    const mft = try allocator.create(memory_forget.MemoryForgetTool);
    mft.* = .{};
    try list.append(allocator, mft.tool());

    // Delegate and schedule tools
    const dlt = try allocator.create(delegate.DelegateTool);
    dlt.* = .{
        .agents = opts.agents orelse &.{},
        .fallback_api_key = opts.fallback_api_key,
        .depth = opts.delegate_depth,
    };
    try list.append(allocator, dlt.tool());

    const scht = try allocator.create(schedule.ScheduleTool);
    scht.* = .{};
    try list.append(allocator, scht.tool());

    // Spawn tool (async subagent)
    const sp = try allocator.create(spawn.SpawnTool);
    sp.* = .{ .manager = opts.subagent_manager };
    try list.append(allocator, sp.tool());

    if (opts.http_enabled) {
        const ht = try allocator.create(http_request.HttpRequestTool);
        ht.* = .{};
        try list.append(allocator, ht.tool());
    }

    if (opts.browser_enabled) {
        const bt = try allocator.create(browser.BrowserTool);
        bt.* = .{};
        try list.append(allocator, bt.tool());
    }

    if (opts.screenshot_enabled) {
        const sst = try allocator.create(screenshot.ScreenshotTool);
        sst.* = .{ .workspace_dir = workspace_dir };
        try list.append(allocator, sst.tool());
    }

    if (opts.composio_api_key) |api_key| {
        const ct = try allocator.create(composio.ComposioTool);
        ct.* = .{ .api_key = api_key, .entity_id = "default" };
        try list.append(allocator, ct.tool());
    }

    if (opts.browser_open_domains) |domains| {
        const bot = try allocator.create(browser_open.BrowserOpenTool);
        bot.* = .{ .allowed_domains = domains };
        try list.append(allocator, bot.tool());
    }

    if (opts.hardware_boards) |boards| {
        const hbi = try allocator.create(hardware_info.HardwareBoardInfoTool);
        hbi.* = .{ .boards = boards };
        try list.append(allocator, hbi.tool());

        const hmt = try allocator.create(hardware_memory.HardwareMemoryTool);
        hmt.* = .{ .boards = boards };
        try list.append(allocator, hmt.tool());

        const i2ct = try allocator.create(i2c.I2cTool);
        i2ct.* = .{};
        try list.append(allocator, i2ct.tool());
    }

    // MCP tools (pre-initialized externally)
    if (opts.mcp_tools) |mt| {
        for (mt) |t| {
            try list.append(allocator, t);
        }
    }

    return list.toOwnedSlice(allocator);
}

/// Create restricted tool set for subagents.
/// Includes: shell, file_read, file_write, file_edit, git, http (if enabled).
/// Excludes: message, spawn, delegate, schedule, memory, composio, browser —
/// to prevent infinite loops and cross-channel side effects.
pub fn subagentTools(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    opts: struct { http_enabled: bool = false },
) ![]Tool {
    var list: std.ArrayList(Tool) = .{};
    errdefer list.deinit(allocator);

    const st = try allocator.create(shell.ShellTool);
    st.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, st.tool());

    const ft = try allocator.create(file_read.FileReadTool);
    ft.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, ft.tool());

    const wt = try allocator.create(file_write.FileWriteTool);
    wt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, wt.tool());

    const et = try allocator.create(file_edit.FileEditTool);
    et.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, et.tool());

    const gt = try allocator.create(git.GitTool);
    gt.* = .{ .workspace_dir = workspace_dir };
    try list.append(allocator, gt.tool());

    if (opts.http_enabled) {
        const ht = try allocator.create(http_request.HttpRequestTool);
        ht.* = .{};
        try list.append(allocator, ht.tool());
    }

    return list.toOwnedSlice(allocator);
}

// ── Tests ───────────────────────────────────────────────────────────

test "tool result ok" {
    const r = ToolResult.ok("hello");
    try std.testing.expect(r.success);
    try std.testing.expectEqualStrings("hello", r.output);
    try std.testing.expect(r.error_msg == null);
}

test "tool result fail" {
    const r = ToolResult.fail("boom");
    try std.testing.expect(!r.success);
    try std.testing.expectEqualStrings("", r.output);
    try std.testing.expectEqualStrings("boom", r.error_msg.?);
}

test "default tools returns four" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        // Free the heap-allocated tool structs
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    try std.testing.expectEqual(@as(usize, 4), tools.len);

    // Verify names
    try std.testing.expectEqualStrings("shell", tools[0].name());
    try std.testing.expectEqualStrings("file_read", tools[1].name());
    try std.testing.expectEqualStrings("file_write", tools[2].name());
    try std.testing.expectEqualStrings("file_edit", tools[3].name());
}

test "all tools has descriptions" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    for (tools) |t| {
        try std.testing.expect(t.description().len > 0);
    }
}

test "all tools have parameter schemas" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    for (tools) |t| {
        const json = t.parametersJson();
        try std.testing.expect(json.len > 0);
        // Should be valid JSON object
        try std.testing.expect(json[0] == '{');
    }
}

test "tool spec generation" {
    const tools = try defaultTools(std.testing.allocator, "/tmp/yc_test");
    defer {
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.free(tools);
    }
    for (tools) |t| {
        const s = t.spec();
        try std.testing.expectEqualStrings(t.name(), s.name);
        try std.testing.expectEqualStrings(t.description(), s.description);
        try std.testing.expect(s.parameters_json.len > 0);
    }
}

test "all tools includes extras when enabled" {
    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{
        .http_enabled = true,
        .browser_enabled = true,
    });
    defer {
        // Free all heap-allocated tool structs (mix of types)
        // Order: shell, file_read, file_write, file_edit, git, image_info,
        //        memory_store, memory_recall, memory_forget, delegate, schedule,
        //        http_request, browser
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.destroy(@as(*git.GitTool, @ptrCast(@alignCast(tools[4].ptr))));
        std.testing.allocator.destroy(@as(*image.ImageInfoTool, @ptrCast(@alignCast(tools[5].ptr))));
        std.testing.allocator.destroy(@as(*memory_store.MemoryStoreTool, @ptrCast(@alignCast(tools[6].ptr))));
        std.testing.allocator.destroy(@as(*memory_recall.MemoryRecallTool, @ptrCast(@alignCast(tools[7].ptr))));
        std.testing.allocator.destroy(@as(*memory_forget.MemoryForgetTool, @ptrCast(@alignCast(tools[8].ptr))));
        std.testing.allocator.destroy(@as(*delegate.DelegateTool, @ptrCast(@alignCast(tools[9].ptr))));
        std.testing.allocator.destroy(@as(*schedule.ScheduleTool, @ptrCast(@alignCast(tools[10].ptr))));
        std.testing.allocator.destroy(@as(*spawn.SpawnTool, @ptrCast(@alignCast(tools[11].ptr))));
        std.testing.allocator.destroy(@as(*http_request.HttpRequestTool, @ptrCast(@alignCast(tools[12].ptr))));
        std.testing.allocator.destroy(@as(*browser.BrowserTool, @ptrCast(@alignCast(tools[13].ptr))));
        std.testing.allocator.free(tools);
    }
    // shell + file_read + file_write + file_edit + git + image_info
    // + memory_store + memory_recall + memory_forget + delegate + schedule
    // + spawn + http_request + browser = 14
    try std.testing.expectEqual(@as(usize, 14), tools.len);
}

test "all tools excludes extras when disabled" {
    const tools = try allTools(std.testing.allocator, "/tmp/yc_test", .{});
    defer {
        // Free all heap-allocated tool structs
        // Order: shell, file_read, file_write, file_edit, git, image_info,
        //        memory_store, memory_recall, memory_forget, delegate, schedule
        std.testing.allocator.destroy(@as(*shell.ShellTool, @ptrCast(@alignCast(tools[0].ptr))));
        std.testing.allocator.destroy(@as(*file_read.FileReadTool, @ptrCast(@alignCast(tools[1].ptr))));
        std.testing.allocator.destroy(@as(*file_write.FileWriteTool, @ptrCast(@alignCast(tools[2].ptr))));
        std.testing.allocator.destroy(@as(*file_edit.FileEditTool, @ptrCast(@alignCast(tools[3].ptr))));
        std.testing.allocator.destroy(@as(*git.GitTool, @ptrCast(@alignCast(tools[4].ptr))));
        std.testing.allocator.destroy(@as(*image.ImageInfoTool, @ptrCast(@alignCast(tools[5].ptr))));
        std.testing.allocator.destroy(@as(*memory_store.MemoryStoreTool, @ptrCast(@alignCast(tools[6].ptr))));
        std.testing.allocator.destroy(@as(*memory_recall.MemoryRecallTool, @ptrCast(@alignCast(tools[7].ptr))));
        std.testing.allocator.destroy(@as(*memory_forget.MemoryForgetTool, @ptrCast(@alignCast(tools[8].ptr))));
        std.testing.allocator.destroy(@as(*delegate.DelegateTool, @ptrCast(@alignCast(tools[9].ptr))));
        std.testing.allocator.destroy(@as(*schedule.ScheduleTool, @ptrCast(@alignCast(tools[10].ptr))));
        std.testing.allocator.destroy(@as(*spawn.SpawnTool, @ptrCast(@alignCast(tools[11].ptr))));
        std.testing.allocator.free(tools);
    }
    // shell + file_read + file_write + file_edit + git + image_info
    // + memory_store + memory_recall + memory_forget + delegate + schedule + spawn = 12
    try std.testing.expectEqual(@as(usize, 12), tools.len);
}

test {
    @import("std").testing.refAllDecls(@This());
}
