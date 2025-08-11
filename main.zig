pub fn main() !void {
    const argv = os.argv;
    if (argv.len != 2) {
        log.err("Expected just one argument", .{});
        return error.Err;
    }
    const path = argv[1];

    var optional_db: ?*c.sqlite3 = undefined;
    if (c.sqlite3_open("db.db", &optional_db) != c.SQLITE_OK) {
        log.err("Can't open the db", .{});
        return error.Err;
    }
    if (optional_db == null) {
        log.err("Can't open the db: null", .{});
        return error.Err;
    }
    defer if (c.sqlite3_close(optional_db) != c.SQLITE_OK)
        log.err("Can't destroy the db", .{});
    const db = optional_db.?;

    try createTables(db);

    var statbuf: Stat = undefined;
    if (stat(path, &statbuf) != 0) {
        log.err("Can't get stat", .{});
        return error.Err;
    }
    try handlePath(db, path);
    if (ISDIR(statbuf.mode)) {
        const dir = try openDirAbsoluteZ(path, .{ .iterate = true });
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| try handlePath(
            db,
            try fs.path.joinZ(allocator, &.{ span(path), entry.basename }),
        );
    }
}

fn createTables(db: *c.sqlite3) !void {
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

fn handlePath(db: *c.struct_sqlite3, path: [*:0]const u8) !void {
    const acl = try Acl.init(path);

    try insertFile(db, acl, path);

    const file_id = c.sqlite3_last_insert_rowid(db);
    try insertUserPerms(db, file_id, acl.users);
    try insertGroupPerms(db, file_id, acl.groups);
}

fn insertFile(db: *c.struct_sqlite3, acl: Acl, path: [*:0]const u8) !void {
    const files_insert_query = try fmt.allocPrint(
        allocator,
        \\INSERT INTO files(
        \\    path,
        \\    user_obj_name,
        \\    user_obj,
        \\    group_obj_name,
        \\    group_obj,
        \\    mask,
        \\    other
        \\) VALUES("{s}", "{s}", {d}, "{s}", {d}, {?d}, {d});
    ,
        .{
            path,
            acl.user_obj_name,
            acl.user_obj,
            acl.group_obj_name,
            acl.group_obj,
            acl.mask,
            acl.other,
        },
    );
    var errmsg: [*c]u8 = undefined;
    if (c.sqlite3_exec(
        db,
        files_insert_query.ptr,
        null,
        null,
        &errmsg,
    ) != c.SQLITE_OK) {
        log.err("Can't insert data: {s}", .{errmsg});
        return error.Err;
    }
}

fn insertUserPerms(
    db: *c.struct_sqlite3,
    file_id: c.sqlite3_int64,
    users: []const PermRecord,
) !void {
    var errmsg: [*c]u8 = undefined;
    for (users) |user| {
        const query = (try fmt.allocPrint(
            allocator,
            "INSERT INTO user_perms(file_id, user_name, perms) VALUES({d}, \"{s}\", {d})",
            .{
                file_id,
                user.name,
                user.perms,
            },
        )).ptr;
        if (c.sqlite3_exec(
            db,
            query,
            null,
            null,
            &errmsg,
        ) != c.SQLITE_OK) {
            log.err("Can't insert user", .{});
            return error.Err;
        }
    }
}

fn insertGroupPerms(
    db: *c.struct_sqlite3,
    file_id: c.sqlite3_int64,
    groups: []const PermRecord,
) !void {
    var errmsg: [*c]u8 = undefined;
    for (groups) |group| {
        const query = (try fmt.allocPrint(
            allocator,
            "INSERT INTO group_perms(file_id, group_name, perms) VALUES({d}, \"{s}\", {d})",
            .{
                file_id,
                group.name,
                group.perms,
            },
        )).ptr;
        if (c.sqlite3_exec(
            db,
            query,
            null,
            null,
            &errmsg,
        ) != c.SQLITE_OK) {
            log.err("Can't insert group: {s}", .{errmsg});
            return error.Err;
        }
    }
}

const Acl = struct {
    user_obj: u3,
    user_obj_name: [*:0]const u8,
    group_obj: u3,
    group_obj_name: [*:0]const u8,
    mask: ?u3,
    other: u3,
    users: []const PermRecord,
    groups: []const PermRecord,

    fn init(path: [*:0]const u8) !@This() {
        const c_acl = c.acl_get_file(path, c.ACL_TYPE_ACCESS) orelse {
            log.err("Can't get an acl of file {s}", .{path});
            return error.Err;
        };

        var acl: @This() = undefined;
        acl.group_obj_name = "";
        acl.user_obj_name = "";
        acl.mask = null;

        var users = ArrayList(PermRecord).init(allocator);
        var groups = ArrayList(PermRecord).init(allocator);

        var statbuf: Stat = undefined;
        if (stat(path, &statbuf) != 0) {
            log.err("Can't get stat", .{});
            return error.Err;
        }

        var entry_id = c.ACL_FIRST_ENTRY;
        var entry: c.acl_entry_t = undefined;
        while (c.acl_get_entry(c_acl, entry_id, &entry) == 1) {
            try handleEntry(entry, &acl, &users, &groups, statbuf);
            entry_id = c.ACL_NEXT_ENTRY;
        }

        acl.users = users.items;
        acl.groups = groups.items;
        return acl;
    }
};

const PermRecord = struct {
    name: [*:0]u8,
    perms: u3,
};

fn handleEntry(
    entry: c.acl_entry_t,
    acl: *Acl,
    users: *ArrayList(PermRecord),
    groups: *ArrayList(PermRecord),
    statbuf: Stat,
) !void {
    var tag_type: c.acl_tag_t = undefined;
    if (c.acl_get_tag_type(entry, &tag_type) == -1) {
        log.err("Can't get an acl tag", .{});
        return error.Err;
    }
    switch (tag_type) {
        c.ACL_USER_OBJ => {
            acl.user_obj = perms(entry);
            acl.user_obj_name = c.getpwuid(statbuf.uid).*.pw_name;
        },
        c.ACL_USER => {
            const uid: *c.uid_t = @ptrCast(@alignCast(c.acl_get_qualifier(entry).?));
            try users.append(.{
                .name = c.getpwuid(uid.*).*.pw_name,
                .perms = perms(entry),
            });
        },
        c.ACL_GROUP_OBJ => {
            acl.group_obj = perms(entry);
            acl.group_obj_name = c.getpwuid(statbuf.gid).*.pw_name;
        },
        c.ACL_GROUP => {
            const gid: *c.gid_t = @ptrCast(@alignCast(c.acl_get_qualifier(entry).?));
            try groups.append(.{
                .name = c.getgrgid(gid.*).*.gr_name,
                .perms = perms(entry),
            });
        },
        c.ACL_MASK => {
            acl.mask = perms(entry);
        },
        c.ACL_OTHER => {
            acl.other = perms(entry);
        },
        else => undefined,
    }
}

fn perms(entry: c.acl_entry_t) u3 {
    var permset: c.acl_permset_t = undefined;
    if (c.acl_get_permset(entry, &permset) == -1) {
        log.err("Can't get permset", .{});
    }

    var output: u3 = 0;
    output |= @intCast(c.acl_get_perm(permset, c.ACL_EXECUTE));
    output |= @intCast(c.acl_get_perm(permset, c.ACL_WRITE) << 1);
    output |= @intCast(c.acl_get_perm(permset, c.ACL_READ) << 2);

    return output;
}

const std = @import("std");
const debug = std.debug;
const log = std.log;
const ArrayList = std.ArrayList;
const fmt = std.fmt;
const os = std.os;
const linux = os.linux;
const stat = linux.stat;
const Stat = linux.Stat;
const ISDIR = linux.S.ISDIR;
const openDirAbsoluteZ = std.fs.openDirAbsoluteZ;
const fs = std.fs;
const span = std.mem.span;

var debug_allocator = std.heap.DebugAllocator(std.heap.DebugAllocatorConfig{}).init;
const allocator = debug_allocator.allocator();

const c = @cImport({
    @cInclude("sys/acl.h");
    @cInclude("acl/libacl.h");
    @cInclude("pwd.h");
    @cInclude("grp.h");
    @cInclude("sqlite3.h");
});
