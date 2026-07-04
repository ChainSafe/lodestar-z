const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const validateDepositSignature = @import("../block/process_deposit.zig").validateDepositSignature;

const BLSPubkey = ct.primitive.BLSPubkey.Type;
const PendingDeposit = ct.electra.PendingDeposit.Type;

const PendingDepositEntry = struct {
    deposits: std.ArrayList(PendingDeposit) = .empty,
    validated_count: usize = 0,
    has_valid_signature: bool = false,

    fn deinit(self: *PendingDepositEntry, allocator: Allocator) void {
        self.deposits.deinit(allocator);
    }
};

pub const PendingDepositsLookup = struct {
    allocator: Allocator,
    deposits_by_pubkey: std.AutoHashMap(BLSPubkey, PendingDepositEntry),

    pub fn buildEmpty(allocator: Allocator) PendingDepositsLookup {
        return .{
            .allocator = allocator,
            .deposits_by_pubkey = std.AutoHashMap(BLSPubkey, PendingDepositEntry).init(allocator),
        };
    }

    pub fn build(comptime fork: ForkSeq, allocator: Allocator, state: *BeaconState(fork)) !PendingDepositsLookup {
        var lookup = PendingDepositsLookup.buildEmpty(allocator);
        errdefer lookup.deinit();

        var pending_deposits = try state.pendingDeposits();
        const pending_deposits_len = try pending_deposits.length();
        var pending_it = pending_deposits.iteratorReadonly(0);

        for (0..pending_deposits_len) |_| {
            const pending_deposit = try pending_it.nextValue(allocator);
            try lookup.add(&pending_deposit);
        }

        return lookup;
    }

    pub fn deinit(self: *PendingDepositsLookup) void {
        var value_iterator = self.deposits_by_pubkey.valueIterator();
        while (value_iterator.next()) |entry| {
            entry.deinit(self.allocator);
        }
        self.deposits_by_pubkey.deinit();
    }

    pub fn add(self: *PendingDepositsLookup, pending_deposit: *const PendingDeposit) !void {
        const result = try self.deposits_by_pubkey.getOrPut(pending_deposit.pubkey);
        if (!result.found_existing) {
            result.value_ptr.* = .{};
        }
        try result.value_ptr.deposits.append(self.allocator, pending_deposit.*);
    }

    pub fn hasPendingValidator(
        self: *PendingDepositsLookup,
        config: *const BeaconConfig,
        pubkey: *const BLSPubkey,
    ) !bool {
        const entry = self.deposits_by_pubkey.getPtr(pubkey.*) orelse return false;
        if (entry.has_valid_signature) return true;
        if (entry.validated_count == entry.deposits.items.len) return false;

        var i = entry.validated_count;
        while (i < entry.deposits.items.len) : (i += 1) {
            const deposit = &entry.deposits.items[i];
            validateDepositSignature(
                config,
                &deposit.pubkey,
                &deposit.withdrawal_credentials,
                deposit.amount,
                deposit.signature,
            ) catch continue;
            entry.has_valid_signature = true;
            entry.validated_count = i + 1;
            return true;
        }

        entry.validated_count = entry.deposits.items.len;
        return false;
    }
};
