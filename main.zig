pub fn main() !void {
    var buf: [fs.max_path_bytes]u8 = undefined;
    const db_path, const path = try parseArgs(&buf) orelse return;

    try openDb(db_path);
    defer if (c.sqlite3_close(db) != c.SQLITE_OK)
        log.err("Can't close the db: {s}", .{c.sqlite3_errmsg(db)});

    try createTables();

    try prepareStmts();
    defer {
        if (c.sqlite3_finalize(insert_file_stmt) != c.SQLITE_OK)
            log.err("Can't finalize a stmt: {s}", .{c.sqlite3_errmsg(db)});
        if (c.sqlite3_finalize(insert_user_perms_stmt) != c.SQLITE_OK)
            log.err("Can't finalize a stmt: {s}", .{c.sqlite3_errmsg(db)});
        if (c.sqlite3_finalize(insert_group_perms_stmt) != c.SQLITE_OK)
            log.err("Can't finalize a stmt: {s}", .{c.sqlite3_errmsg(db)});
    }

    try handleRootPath(path);
}

fn handleRootPath(path: [*:0]u8) !void {
    var statbuf: Stat = undefined;
    if (stat(path, &statbuf) != 0) {
        log.err("Can't get stat", .{});
        return error.Err;
    }

    parent_progress_node = Progress.start(.{});
    handlePath(path);
    if (handle_path_err) |err| return err;
    if (ISDIR(statbuf.mode)) {
        const dir = try openDirAbsoluteZ(path, .{ .iterate = true });
        var walker = try dir.walk(allocator);
        var pool: Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();
        var wg = WaitGroup{};
        while (try walker.next()) |entry|
            pool.spawnWg(
                &wg,
                handlePath,
                .{try fs.path.joinZ(allocator, &.{ span(path), entry.path })},
            );
        wg.wait();
        if (handle_path_err) |err| return err;
    }
}

fn parseArgs(buf: []u8) !?[2][*:0]u8 {
    const argv = os.argv;
    if (argv.len != 2 and argv.len != 3) {
        log.err("Expected 1 or 2 arguments, found {d}", .{argv.len - 1});
        return error.Err;
    }

    if (argv.len == 2) {
        if (mem.eql(u8, span(argv[1]), "--help")) {
            try std.io.getStdOut().writeAll("macl path_to_sqlite3_db path_to_scan\n");
            return null;
        } else {
            log.err("An unrecognized command", .{});
            return error.Err;
        }
    }

    const db_path = argv[1];
    const path = if (fs.path.isAbsoluteZ(argv[2]))
        argv[2]
    else out: {
        const realpath = try cwd().realpathZ(argv[2], buf);
        buf[realpath.len] = 0;
        break :out buf[0..realpath.len :0].ptr;
    };
    return .{ db_path, path };
}

fn openDb(path: [*:0]const u8) !void {
    var opt_db: ?*c.sqlite3 = undefined;
    if (c.sqlite3_open(path, &opt_db) != c.SQLITE_OK) {
        log.err("Can't open the db", .{});
        return error.Err;
    }
    if (opt_db == null) {
        log.err("Can't open the db: null", .{});
        return error.Err;
    }
    db = opt_db.?;
}

fn prepareStmts() !void {
    var tail: ?[*]const u8 = undefined;

    var opt_insert_file_stmt: ?*c.sqlite3_stmt = undefined;
    if (c.sqlite3_prepare_v2(
        db,
        \\INSERT INTO files(
        \\    path,
        \\    user_obj_name,
        \\    user_obj,
        \\    group_obj_name,
        \\    group_obj,
        \\    mask,
        \\    other
        \\) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
    ,
        1024,
        &opt_insert_file_stmt,
        &tail,
    ) != c.SQLITE_OK) {
        log.err(
            "Can't prepare a file insertion statement: {s}",
            .{c.sqlite3_errmsg(db)},
        );
        return error.Err;
    }
    assert(tail.?[0] == 0);
    insert_file_stmt = opt_insert_file_stmt.?;

    var opt_insert_user_perms_stmt: ?*c.sqlite3_stmt = undefined;
    if (c.sqlite3_prepare_v2(
        db,
        "INSERT INTO user_perms(file_id, user_name, perms) VALUES(?1, ?2, ?3)",
        1024,
        &opt_insert_user_perms_stmt,
        &tail,
    ) != c.SQLITE_OK) {
        log.err(
            "Can't prepare an user perms insertion statement: {s}",
            .{c.sqlite3_errmsg(db)},
        );
        return error.Err;
    }
    assert(tail.?[0] == 0);
    insert_user_perms_stmt = opt_insert_user_perms_stmt.?;

    var opt_insert_group_perms_stmt: ?*c.sqlite3_stmt = undefined;
    if (c.sqlite3_prepare_v2(
        db,
        "INSERT INTO group_perms(file_id, group_name, perms) VALUES(?1, ?2, ?3)",
        1024,
        &opt_insert_group_perms_stmt,
        &tail,
    ) != c.SQLITE_OK) {
        log.err(
            "Can't prepare a group perms insertion statement: {s}",
            .{c.sqlite3_errmsg(db)},
        );
        return error.Err;
    }
    assert(tail.?[0] == 0);
    insert_group_perms_stmt = opt_insert_group_perms_stmt.?;
}

fn createTables() !void {
    var errmsg: [*c]u8 = undefined;
    if (c.sqlite3_exec(
        db,
        \\CREATE TABLE IF NOT EXISTS files(
        \\    id INTEGER PRIMARY KEY,
        \\    path TEXT NOT NULL,
        \\    user_obj_name TEXT NOT NULL,
        \\    user_obj INTEGER NOT NULL,
        \\    group_obj_name TEXT NOT NULL,
        \\    group_obj INTEGER NOT NULL,
        \\    mask INTEGER,
        \\    other INTEGER NOT NULL
        \\);
        \\CREATE TABLE IF NOT EXISTS user_perms(
        \\    file_id INTEGER NOT NULL,
        \\    user_name TEXT NOT NULL,
        \\    perms INTEGER NOT NULL,
        \\    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        \\);
        \\CREATE TABLE IF NOT EXISTS group_perms(
        \\    file_id INTEGER NOT NULL,
        \\    group_name TEXT NOT NULL,
        \\    perms INTEGER NOT NULL,
        \\    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        \\);
    ,
        null,
        null,
        &errmsg,
    ) != c.SQLITE_OK) {
        log.err("Can't create tables: {s}", .{errmsg});
        return error.Err;
    }
}

fn handlePath(path: [*:0]const u8) void {
    const progress_node = parent_progress_node.start(span(path), 0);
    defer progress_node.end();

    const acl = Acl.init(allocator, path) catch |err| {
        setHandlePathErr(err);
        return;
    };

    const file_id = insertFile(acl, path) catch |err| {
        setHandlePathErr(err);
        return;
    };

    insertUserPerms(file_id, acl.users) catch |err| {
        setHandlePathErr(err);
        return;
    };

    insertGroupPerms(file_id, acl.groups) catch |err| {
        setHandlePathErr(err);
        return;
    };
}

var parent_progress_node: Progress.Node = undefined;

fn setHandlePathErr(err: anyerror) void {
    handle_path_err_mtx.lock();
    handle_path_err = err;
    handle_path_err_mtx.unlock();
}

var handle_path_err_mtx = Mutex{};
var handle_path_err: ?anyerror = null;

fn insertFile(acl: Acl, path: [*:0]const u8) !c.sqlite3_int64 {
    insert_file_stmt_mtx.lock();
    defer insert_file_stmt_mtx.unlock();
    if (c.sqlite3_reset(insert_file_stmt) != c.SQLITE_OK) {
        log.err("Can't reset a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }

    try bind(insert_file_stmt, .{
        path,
        acl.user_obj_name,
        acl.user_obj,
        acl.group_obj_name,
        acl.group_obj,
        acl.mask,
        acl.other,
    });

    if (c.sqlite3_step(insert_file_stmt) != c.SQLITE_DONE) {
        log.err("Can't insert file: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
    return c.sqlite3_last_insert_rowid(db);
}

var insert_file_stmt: *c.sqlite3_stmt = undefined;
var insert_file_stmt_mtx = Mutex{};

fn insertUserPerms(file_id: c.sqlite3_int64, users: []const Acl.PermRecord) !void {
    insert_user_perms_stmt_mtx.lock();
    defer insert_user_perms_stmt_mtx.unlock();
    for (users) |user| {
        if (c.sqlite3_reset(insert_user_perms_stmt) != c.SQLITE_OK) {
            log.err(
                "Can't reset an user perms insertion statement: {s}",
                .{c.sqlite3_errmsg(db)},
            );
            return error.Err;
        }

        try bind(insert_user_perms_stmt, .{ file_id, user.name, user.perms });

        if (c.sqlite3_step(insert_user_perms_stmt) != c.SQLITE_DONE) {
            log.err("Can't insert user perms: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
    }
}

var insert_user_perms_stmt: *c.sqlite3_stmt = undefined;
var insert_user_perms_stmt_mtx = Mutex{};

fn insertGroupPerms(file_id: c.sqlite3_int64, groups: []const Acl.PermRecord) !void {
    insert_group_perms_stmt_mtx.lock();
    defer insert_group_perms_stmt_mtx.unlock();
    for (groups) |group| {
        if (c.sqlite3_reset(insert_group_perms_stmt) != c.SQLITE_OK) {
            log.err(
                "Can't reset a group perms insertion statement: {s}",
                .{c.sqlite3_errmsg(db)},
            );
            return error.Err;
        }

        try bind(insert_group_perms_stmt, .{ file_id, group.name, group.perms });

        if (c.sqlite3_step(insert_group_perms_stmt) != c.SQLITE_DONE) {
            log.err("Can't insert a group perms: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
    }
}

var insert_group_perms_stmt: *c.sqlite3_stmt = undefined;
var insert_group_perms_stmt_mtx = Mutex{};

fn bind(stmt: *c.sqlite3_stmt, args: anytype) !void {
    inline for (@typeInfo(@TypeOf(args)).@"struct".fields) |field| {
        const id = comptime parseInt(u8, field.name, 10) catch unreachable;
        switch (field.type) {
            [*:0]const u8, [*:0]u8 => if (c.sqlite3_bind_text(
                stmt,
                id + 1,
                args[id],
                @intCast(len(args[id])),
                c.SQLITE_TRANSIENT,
            ) != c.SQLITE_OK) {
                log.err("Can't bind a statement: {s}", .{c.sqlite3_errmsg(db)});
                return error.Err;
            },
            u3 => if (c.sqlite3_bind_int(stmt, id + 1, args[id]) != c.SQLITE_OK) {
                log.err("Can't bind a statement: {s}", .{c.sqlite3_errmsg(db)});
                return error.Err;
            },
            ?u3 => {
                const res = if (args[id]) |arg|
                    c.sqlite3_bind_int(stmt, id + 1, arg)
                else
                    c.sqlite3_bind_null(stmt, id + 1);
                if (res != c.SQLITE_OK) {
                    log.err("Can't bind a statement: {s}", .{c.sqlite3_errmsg(db)});
                    return error.Err;
                }
            },
            c_longlong => if (c.sqlite3_bind_int64(stmt, id + 1, args[id]) != c.SQLITE_OK) {
                log.err("Can't bind a statement: {s}", .{c.sqlite3_errmsg(db)});
                return error.Err;
            },
            else => @compileError("Unimplemented binding for " ++ @typeName(field.type)),
        }
    }
}

var db: *c.sqlite3 = undefined;

var debug_allocator = std.heap.DebugAllocator(.{}).init;
const allocator = debug_allocator.allocator();

const std = @import("std");
const log = std.log;
const getStdErr = std.io.getStdErr;
const Progress = std.Progress;

const fmt = std.fmt;
const parseInt = fmt.parseInt;

const debug = std.debug;
const assert = debug.assert;

const os = std.os;
const linux = os.linux;
const stat = linux.stat;
const Stat = linux.Stat;
const ISDIR = linux.S.ISDIR;

const fs = std.fs;
const openDirAbsoluteZ = fs.openDirAbsoluteZ;
const cwd = fs.cwd;

const mem = std.mem;
const span = mem.span;
const len = mem.len;

const Thread = std.Thread;
const Pool = Thread.Pool;
const WaitGroup = Thread.WaitGroup;
const Mutex = Thread.Mutex;

const Acl = @import("Acl.zig");

const c = @cImport({
    @cInclude("sqlite3.h");
});
