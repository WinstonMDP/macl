///! See acl manual page
/// Permissions of an owner
user_obj: u3,
/// An owner name
user_obj_name: [*:0]const u8,
/// Permissions of an owner group
group_obj: u3,
/// An owner group name
group_obj_name: [*:0]const u8,
mask: ?u3,
other: u3,
users: []const PermRecord,
groups: []const PermRecord,

pub fn init(allocator: Allocator, path: [*:0]const u8) !@This() {
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

pub const PermRecord = struct {
    name: [*:0]u8,
    perms: u3,
};

fn handleEntry(
    entry: c.acl_entry_t,
    acl: *@This(),
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
const log = std.log;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const os = std.os;
const linux = os.linux;
const stat = linux.stat;
const Stat = linux.Stat;

const c = @cImport({
    @cInclude("sys/acl.h");
    @cInclude("acl/libacl.h");
    @cInclude("pwd.h");
    @cInclude("grp.h");
    @cInclude("sqlite3.h");
});
