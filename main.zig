pub fn main() !void {
    const argv = os.argv;
    if (argv.len != 2) {
        log.err("Expected just one argument, found {d}", .{argv.len - 1});
        return error.Err;
    }
    const path = argv[1];

    try openDb();
    defer if (c.sqlite3_close(db) != c.SQLITE_OK)
        log.err("Can't close the db: {s}", .{c.sqlite3_errmsg(db)});

    try createTables();

    var statbuf: Stat = undefined;
    if (stat(path, &statbuf) != 0) {
        log.err("Can't get stat", .{});
        return error.Err;
    }

    try prepareStmts();
    defer {
        if (c.sqlite3_finalize(insert_file_stmt) != c.SQLITE_OK)
            log.err("Can't finalize a stmt: {s}", .{c.sqlite3_errmsg(db)});
        if (c.sqlite3_finalize(insert_user_perms_stmt) != c.SQLITE_OK)
            log.err("Can't finalize a stmt: {s}", .{c.sqlite3_errmsg(db)});
        if (c.sqlite3_finalize(insert_group_perms_stmt) != c.SQLITE_OK)
            log.err("Can't finalize a stmt: {s}", .{c.sqlite3_errmsg(db)});
    }

    try handlePath(path);
    if (ISDIR(statbuf.mode)) {
        const dir = try openDirAbsoluteZ(path, .{ .iterate = true });
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next()) |entry|
            try handlePath(try fs.path.joinZ(allocator, &.{ span(path), entry.path }));
    }
}

fn openDb() !void {
    var opt_db: ?*c.sqlite3 = undefined;
    if (c.sqlite3_open("db.db", &opt_db) != c.SQLITE_OK) {
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
            "Can't prepare an file insertion statement: {s}",
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

fn handlePath(path: [*:0]const u8) !void {
    const acl = try Acl.init(allocator, path);

    try insertFile(acl, path);

    const file_id = c.sqlite3_last_insert_rowid(db);
    try insertUserPerms(file_id, acl.users);
    try insertGroupPerms(file_id, acl.groups);
}

fn insertFile(acl: Acl, path: [*:0]const u8) !void {
    if (c.sqlite3_reset(insert_file_stmt) != c.SQLITE_OK) {
        log.err("Can't reset a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }

    if (c.sqlite3_bind_text(
        insert_file_stmt,
        1,
        path,
        @intCast(len(path)),
        c.SQLITE_TRANSIENT,
    ) != c.SQLITE_OK) {
        log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
    if (c.sqlite3_bind_text(
        insert_file_stmt,
        2,
        acl.user_obj_name,
        @intCast(len(acl.group_obj_name)),
        c.SQLITE_TRANSIENT,
    ) != c.SQLITE_OK) {
        log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
    if (c.sqlite3_bind_int(insert_file_stmt, 3, acl.user_obj) != c.SQLITE_OK) {
        log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
    if (c.sqlite3_bind_text(
        insert_file_stmt,
        4,
        acl.group_obj_name,
        @intCast(len(acl.group_obj_name)),
        c.SQLITE_TRANSIENT,
    ) != c.SQLITE_OK) {
        log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
    if (c.sqlite3_bind_int(insert_file_stmt, 5, acl.group_obj) != c.SQLITE_OK) {
        log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
    if (acl.mask) |mask| {
        if (c.sqlite3_bind_int(insert_file_stmt, 6, mask) != c.SQLITE_OK) {
            log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
    } else if (c.sqlite3_bind_null(insert_file_stmt, 6) != c.SQLITE_OK) {
        log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
    if (c.sqlite3_bind_int(insert_file_stmt, 7, acl.other) != c.SQLITE_OK) {
        log.err("Can't bind a file insertion statement: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }

    if (c.sqlite3_step(insert_file_stmt) != c.SQLITE_DONE) {
        log.err("Can't insert file: {s}", .{c.sqlite3_errmsg(db)});
        return error.Err;
    }
}

var insert_file_stmt: *c.sqlite3_stmt = undefined;

fn insertUserPerms(
    file_id: c.sqlite3_int64,
    users: []const Acl.PermRecord,
) !void {
    for (users) |user| {
        if (c.sqlite3_reset(insert_user_perms_stmt) != c.SQLITE_OK) {
            log.err(
                "Can't reset an user perms insertion statement: {s}",
                .{c.sqlite3_errmsg(db)},
            );
            return error.Err;
        }

        if (c.sqlite3_bind_int64(insert_user_perms_stmt, 1, file_id) != c.SQLITE_OK) {
            log.err(
                "Can't bind an user perms insertion statement: {s}",
                .{c.sqlite3_errmsg(db)},
            );
            return error.Err;
        }
        if (c.sqlite3_bind_text(
            insert_user_perms_stmt,
            2,
            user.name,
            @intCast(len(user.name)),
            c.SQLITE_TRANSIENT,
        ) != c.SQLITE_OK) {
            log.err("Can't bind an user perms insertion statement: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
        if (c.sqlite3_bind_int(insert_user_perms_stmt, 3, user.perms) != c.SQLITE_OK) {
            log.err("Can't bind an user perms insertion statement: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }

        if (c.sqlite3_step(insert_user_perms_stmt) != c.SQLITE_DONE) {
            log.err("Can't insert user perms: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
    }
}

var insert_user_perms_stmt: *c.sqlite3_stmt = undefined;

fn insertGroupPerms(file_id: c.sqlite3_int64, groups: []const Acl.PermRecord) !void {
    for (groups) |group| {
        if (c.sqlite3_reset(insert_group_perms_stmt) != c.SQLITE_OK) {
            log.err(
                "Can't reset a group perms insertion statement: {s}",
                .{c.sqlite3_errmsg(db)},
            );
            return error.Err;
        }

        if (c.sqlite3_bind_int64(insert_group_perms_stmt, 1, file_id) != c.SQLITE_OK) {
            log.err("Can't bind a group perms insertion statement: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
        if (c.sqlite3_bind_text(
            insert_group_perms_stmt,
            2,
            group.name,
            @intCast(len(group.name)),
            c.SQLITE_TRANSIENT,
        ) != c.SQLITE_OK) {
            log.err("Can't bind a group perms insertion statement: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
        if (c.sqlite3_bind_int(insert_group_perms_stmt, 3, group.perms) != c.SQLITE_OK) {
            log.err("Can't bind a group perms insertion statement: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }

        if (c.sqlite3_step(insert_group_perms_stmt) != c.SQLITE_DONE) {
            log.err("Can't insert a group perms: {s}", .{c.sqlite3_errmsg(db)});
            return error.Err;
        }
    }
}

var insert_group_perms_stmt: *c.sqlite3_stmt = undefined;

var db: *c.sqlite3 = undefined;

var debug_allocator = std.heap.DebugAllocator(std.heap.DebugAllocatorConfig{}).init;
const allocator = debug_allocator.allocator();

const std = @import("std");
const log = std.log;
const fmt = std.fmt;

const debug = std.debug;
const assert = debug.assert;

const os = std.os;
const linux = os.linux;
const stat = linux.stat;
const Stat = linux.Stat;
const ISDIR = linux.S.ISDIR;

const fs = std.fs;
const openDirAbsoluteZ = fs.openDirAbsoluteZ;

const mem = std.mem;
const span = mem.span;
const len = mem.len;

const Acl = @import("Acl.zig");

const c = @cImport({
    @cInclude("sqlite3.h");
});
