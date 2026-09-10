const Options = @import("options.zig").Options;

pub const Progress = enum { done, credits, events, storage };

pub const Credits = struct {
    input: usize,
    output: usize,
    items: usize,
    calls: usize,
    work: usize,
    fields: usize,

    pub fn peer(options: *const Options) Credits {
        return .{
            .input = options.input_per_peer,
            .output = options.output_per_peer,
            .items = options.items_per_peer,
            .calls = options.calls_per_peer,
            .work = options.decompress_per_peer_bytes,
            .fields = options.fields_per_peer,
        };
    }
};

pub const Turn = struct {
    now: @import("../types.zig").Now,
    budget: Credits,
    events: []@import("gossipsub.zig").Event,
    count: usize = 0,
    arena: []u8,
    used: usize = 0,
    scratch: []u8,
    large_used: bool = false,

    pub fn init(options: *const Options, now: @import("../types.zig").Now, events: []@import("gossipsub.zig").Event, arena: []u8, scratch: []u8) Turn {
        return .{
            .now = now,
            .budget = .{
                .input = options.input_per_pump,
                .output = options.output_per_pump,
                .items = options.items_per_pump,
                .calls = options.calls_per_pump,
                .work = options.work_per_pump,
                .fields = options.fields_per_pump,
            },
            .events = events,
            .arena = arena,
            .scratch = scratch,
        };
    }

    pub fn workspace(self: *Turn, peer: *Credits) Workspace {
        return .{ .arena = self.arena, .scratch = self.scratch, .used = &self.used, .peer_work = &peer.work, .work = &self.budget.work, .large_used = &self.large_used, .event_available = self.count < self.events.len };
    }
};

pub const Workspace = struct {
    arena: []u8,
    scratch: []u8,
    used: *usize,
    peer_work: *usize,
    work: *usize,
    large_used: *bool,
    event_available: bool,

    pub fn charge(workspace: *const Workspace, options: *const Options, compressed: usize, decoded: usize) bool {
        const cost = compressed * 2 + decoded * 2;
        if (cost <= workspace.work.* and cost <= workspace.peer_work.*) {
            workspace.work.* -= cost;
            workspace.peer_work.* -= cost;
            return true;
        }
        if (!workspace.large_used.* and cost > @min(options.work_per_pump, options.decompress_per_peer_bytes)) {
            workspace.large_used.* = true;
            return true;
        }
        return false;
    }
};
