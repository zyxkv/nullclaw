//! Backend Registry — comptime descriptors for all memory backends.
//!
//! Each backend declares its name, capabilities, path requirements, and
//! factory function.  The path resolver (`resolvePaths`) centralises the
//! `joinZ` logic that was previously duplicated across 6 entry points.

const std = @import("std");
const build_options = @import("build_options");
const config_types = @import("../../config_types.zig");
const root = @import("../root.zig");
const memory_lru = @import("memory_lru.zig");
const pg = if (build_options.enable_postgres) @import("postgres.zig") else struct {};
const redis_engine = @import("redis.zig");
const lancedb_engine = @import("lancedb.zig");
const api_engine = @import("api.zig");

// ── Capability & descriptor types ────────────────────────────────

pub const BackendCapabilities = struct {
    supports_keyword_rank: bool, // FTS5 BM25
    supports_session_store: bool, // saveMessage / loadMessages
    supports_transactions: bool, // BEGIN / COMMIT
    supports_outbox: bool, // durable vector-sync
};

pub const BackendDescriptor = struct {
    name: []const u8,
    label: []const u8,
    auto_save_default: bool,
    capabilities: BackendCapabilities,
    needs_db_path: bool, // sqlite, lucid → true
    needs_workspace: bool, // markdown, lucid → true
    create: *const fn (std.mem.Allocator, BackendConfig) anyerror!BackendInstance,
};

pub const BackendConfig = struct {
    db_path: ?[*:0]const u8,
    workspace_dir: []const u8,
    postgres_url: ?[*:0]const u8 = null,
    postgres_schema: []const u8 = "public",
    postgres_table: []const u8 = "memories",
    api_config: ?config_types.MemoryApiConfig = null,
};

pub const BackendInstance = struct {
    memory: root.Memory,
    session_store: ?root.SessionStore,
};

// ── Comptime registry ────────────────────────────────────────────

const base_backends = [_]BackendDescriptor{
    .{
        .name = "sqlite",
        .label = "SQLite with FTS5 search (recommended)",
        .auto_save_default = true,
        .capabilities = .{ .supports_keyword_rank = true, .supports_session_store = true, .supports_transactions = true, .supports_outbox = true },
        .needs_db_path = true,
        .needs_workspace = false,
        .create = &createSqlite,
    },
    .{
        .name = "markdown",
        .label = "Markdown files — simple, human-readable",
        .auto_save_default = true,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .needs_db_path = false,
        .needs_workspace = true,
        .create = &createMarkdown,
    },
    .{
        .name = "lucid",
        .label = "Lucid — SQLite + cross-project memory sync via lucid CLI",
        .auto_save_default = true,
        .capabilities = .{ .supports_keyword_rank = true, .supports_session_store = true, .supports_transactions = true, .supports_outbox = true },
        .needs_db_path = true,
        .needs_workspace = true,
        .create = &createLucid,
    },
    .{
        .name = "memory",
        .label = "In-memory LRU — no persistence, ideal for testing",
        .auto_save_default = false,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .needs_db_path = false,
        .needs_workspace = false,
        .create = &createMemoryLru,
    },
    .{
        .name = "redis",
        .label = "Redis — distributed in-memory store with optional TTL",
        .auto_save_default = true,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .needs_db_path = false,
        .needs_workspace = false,
        .create = &createRedis,
    },
    .{
        .name = "lancedb",
        .label = "LanceDB — SQLite + vector-augmented recall",
        .auto_save_default = true,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .needs_db_path = true,
        .needs_workspace = false,
        .create = &createLanceDb,
    },
    .{
        .name = "api",
        .label = "HTTP API — delegate to external REST service",
        .auto_save_default = true,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = true, .supports_transactions = false, .supports_outbox = false },
        .needs_db_path = false,
        .needs_workspace = false,
        .create = &createApi,
    },
    .{
        .name = "none",
        .label = "None — disable persistent memory",
        .auto_save_default = false,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .needs_db_path = false,
        .needs_workspace = false,
        .create = &createNone,
    },
};

const pg_backends = if (build_options.enable_postgres) [_]BackendDescriptor{.{
    .name = "postgres",
    .label = "PostgreSQL — remote/shared memory store",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = true, .supports_transactions = true, .supports_outbox = true },
    .needs_db_path = false,
    .needs_workspace = false,
    .create = &createPostgres,
}} else [0]BackendDescriptor{};

pub const all = base_backends ++ pg_backends;

// ── Lookup ───────────────────────────────────────────────────────

pub fn findBackend(name: []const u8) ?*const BackendDescriptor {
    for (&all) |*desc| {
        if (std.mem.eql(u8, desc.name, name)) return desc;
    }
    return null;
}

// ── Path resolver ────────────────────────────────────────────────

pub fn resolvePaths(
    allocator: std.mem.Allocator,
    desc: *const BackendDescriptor,
    workspace_dir: []const u8,
    postgres_cfg: ?config_types.MemoryPostgresConfig,
    api_cfg: ?config_types.MemoryApiConfig,
) !BackendConfig {
    const db_path: ?[*:0]const u8 = if (desc.needs_db_path)
        try std.fs.path.joinZ(allocator, &.{ workspace_dir, "memory.db" })
    else
        null;

    var pg_url: ?[*:0]const u8 = null;
    var pg_schema: []const u8 = "public";
    var pg_table: []const u8 = "memories";
    if (postgres_cfg) |pcfg| {
        if (pcfg.url.len > 0) {
            pg_url = try allocator.dupeZ(u8, pcfg.url);
        }
        pg_schema = pcfg.schema;
        pg_table = pcfg.table;
    }

    return .{
        .db_path = db_path,
        .workspace_dir = workspace_dir,
        .postgres_url = pg_url,
        .postgres_schema = pg_schema,
        .postgres_table = pg_table,
        .api_config = api_cfg,
    };
}

// ── Factory wrappers ─────────────────────────────────────────────

fn createSqlite(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.SqliteMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try root.SqliteMemory.init(allocator, cfg.db_path.?);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn createMarkdown(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.MarkdownMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try root.MarkdownMemory.init(allocator, cfg.workspace_dir);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createLucid(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.LucidMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try root.LucidMemory.init(allocator, cfg.db_path.?, cfg.workspace_dir);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn createMemoryLru(allocator: std.mem.Allocator, _: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(memory_lru.InMemoryLruMemory);
    impl_.* = memory_lru.InMemoryLruMemory.init(allocator, 1000);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createRedis(allocator: std.mem.Allocator, _: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(redis_engine.RedisMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try redis_engine.RedisMemory.init(allocator, .{});
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createLanceDb(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(lancedb_engine.LanceDbMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try lancedb_engine.LanceDbMemory.init(allocator, cfg.db_path.?, null, .{});
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createApi(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const api_cfg = cfg.api_config orelse return error.MissingApiConfig;
    const impl_ = try allocator.create(api_engine.ApiMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try api_engine.ApiMemory.init(allocator, api_cfg);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn createNone(allocator: std.mem.Allocator, _: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.NoneMemory);
    impl_.* = root.NoneMemory.init();
    impl_.allocator = allocator;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createPostgres(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    if (!build_options.enable_postgres) return error.PostgresNotEnabled;
    const url = cfg.postgres_url orelse return error.MissingPostgresUrl;
    const impl_ = try allocator.create(pg.PostgresMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try pg.PostgresMemory.init(allocator, url, cfg.postgres_schema, cfg.postgres_table);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

// ── Tests ────────────────────────────────────────────────────────

test "registry length" {
    const expected: usize = if (build_options.enable_postgres) 9 else 8;
    try std.testing.expectEqual(expected, all.len);
}

test "findBackend sqlite" {
    const desc = findBackend("sqlite") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("sqlite", desc.name);
    try std.testing.expect(desc.capabilities.supports_keyword_rank);
    try std.testing.expect(desc.capabilities.supports_session_store);
    try std.testing.expect(desc.capabilities.supports_transactions);
    try std.testing.expect(desc.capabilities.supports_outbox);
    try std.testing.expect(desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend markdown" {
    const desc = findBackend("markdown") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("markdown", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend lucid" {
    const desc = findBackend("lucid") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("lucid", desc.name);
    try std.testing.expect(desc.capabilities.supports_keyword_rank);
    try std.testing.expect(desc.needs_db_path);
    try std.testing.expect(desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend none" {
    const desc = findBackend("none") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("none", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(!desc.auto_save_default);
}

test "findBackend redis" {
    const desc = findBackend("redis") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("redis", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend lancedb" {
    const desc = findBackend("lancedb") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("lancedb", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend api" {
    const desc = findBackend("api") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("api", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.capabilities.supports_transactions);
    try std.testing.expect(!desc.capabilities.supports_outbox);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend unknown returns null" {
    try std.testing.expect(findBackend("nonexistent") == null);
}

test "findBackend empty returns null" {
    try std.testing.expect(findBackend("") == null);
}

test "resolvePaths sqlite has db_path" {
    const desc = findBackend("sqlite") orelse return error.TestUnexpectedResult;
    const cfg = try resolvePaths(std.testing.allocator, desc, "/tmp/ws", null, null);
    defer if (cfg.db_path) |p| std.testing.allocator.free(std.mem.span(p));

    try std.testing.expect(cfg.db_path != null);
    const path_slice = std.mem.span(cfg.db_path.?);
    try std.testing.expect(std.mem.endsWith(u8, path_slice, "memory.db"));
    try std.testing.expectEqualStrings("/tmp/ws", cfg.workspace_dir);
}

test "resolvePaths markdown has no db_path" {
    const desc = findBackend("markdown") orelse return error.TestUnexpectedResult;
    const cfg = try resolvePaths(std.testing.allocator, desc, "/tmp/ws", null, null);

    try std.testing.expect(cfg.db_path == null);
    try std.testing.expectEqualStrings("/tmp/ws", cfg.workspace_dir);
}

test "resolvePaths none has no db_path" {
    const desc = findBackend("none") orelse return error.TestUnexpectedResult;
    const cfg = try resolvePaths(std.testing.allocator, desc, "/tmp/ws", null, null);

    try std.testing.expect(cfg.db_path == null);
    try std.testing.expectEqualStrings("/tmp/ws", cfg.workspace_dir);
}

test "createNone produces working memory" {
    const instance = try createNone(std.testing.allocator, .{
        .db_path = null,
        .workspace_dir = "/tmp",
    });
    defer instance.memory.deinit();

    try std.testing.expectEqualStrings("none", instance.memory.name());
    try std.testing.expectEqual(@as(usize, 0), try instance.memory.count());
    try std.testing.expect(instance.memory.healthCheck());
}

test "createNone returns session_store null" {
    const instance = try createNone(std.testing.allocator, .{
        .db_path = null,
        .workspace_dir = "/tmp",
    });
    defer instance.memory.deinit();

    try std.testing.expect(instance.session_store == null);
}
