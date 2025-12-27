/// To implement a TreeView type, you must implement the following functions:
///   pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !*Self
///   pub fn deinit(self: *Self) void
///   pub fn commit(self: *Self) !void
///   pub fn getRoot(self: *const Self) Node.Id
///   pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void
///
/// it usually also contains these fields:
///   allocator: Allocator
///   pool: *Node.Pool
///   root: Node.Id
pub fn assertTreeViewType(comptime TV: type) void {
    if (!@hasDecl(TV, "init")) {
        @compileError("TreeView type must implement 'init' function");
    }

    if (!@hasDecl(TV, "deinit")) {
        @compileError("TreeView type must implement 'deinit' function");
    }

    if (!@hasDecl(TV, "commit")) {
        @compileError("TreeView type must implement 'commit' function");
    }

    if (!@hasDecl(TV, "getRoot")) {
        @compileError("TreeView type must implement 'getRoot' function");
    }

    if (!@hasDecl(TV, "hashTreeRoot")) {
        @compileError("TreeView type must implement 'hashTreeRoot' function");
    }
}
