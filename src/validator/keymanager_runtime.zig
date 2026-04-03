const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_context = @import("api").context;
const DeleteKeyResult = api_context.DeleteKeyResult;
const KeymanagerCallback = api_context.KeymanagerCallback;
const RemoteKeyInfo = api_context.RemoteKeyInfo;
const ValidatorKeyInfo = api_context.ValidatorKeyInfo;

const keystore_mod = @import("keystore.zig");
const persisted_keys = @import("persisted_keys.zig");
const KeymanagerAuth = @import("keymanager_auth.zig").KeymanagerAuth;
const signing = @import("signing.zig");
const validator_mod = @import("validator.zig");
const ValidatorClient = validator_mod.ValidatorClient;
const validator_store_mod = @import("validator_store.zig");
const SignerKind = validator_store_mod.SignerKind;
const interchange_mod = @import("interchange.zig");
const validator_types = @import("types.zig");
const ProposerConfig = validator_types.ProposerConfig;
const startup_signers = @import("startup_signers.zig");
const consensus_types = @import("consensus_types");

pub const KeymanagerRuntime = struct {
    allocator: Allocator,
    io: Io,
    client: *ValidatorClient,
    auth: ?KeymanagerAuth = null,
    proposer_config_write_enabled: bool,

    pub fn init(
        io: Io,
        allocator: Allocator,
        client: *ValidatorClient,
        auth: ?KeymanagerAuth,
        proposer_config_write_enabled: bool,
    ) KeymanagerRuntime {
        return .{
            .allocator = allocator,
            .io = io,
            .client = client,
            .auth = auth,
            .proposer_config_write_enabled = proposer_config_write_enabled,
        };
    }

    pub fn deinit(self: *KeymanagerRuntime) void {
        if (self.auth) |*auth| auth.deinit();
    }

    pub fn callback(self: *KeymanagerRuntime) KeymanagerCallback {
        return .{
            .ptr = self,
            .validateTokenFn = validateToken,
            .listKeysFn = listKeys,
            .importKeyFn = importKey,
            .deleteKeyFn = deleteKey,
            .listRemoteKeysFn = listRemoteKeys,
            .importRemoteKeyFn = importRemoteKey,
            .deleteRemoteKeyFn = deleteRemoteKey,
            .getFeeRecipientFn = getFeeRecipient,
            .setFeeRecipientFn = setFeeRecipient,
            .deleteFeeRecipientFn = deleteFeeRecipient,
            .getGraffitiFn = getGraffiti,
            .setGraffitiFn = setGraffiti,
            .deleteGraffitiFn = deleteGraffiti,
            .getGasLimitFn = getGasLimit,
            .setGasLimitFn = setGasLimit,
            .deleteGasLimitFn = deleteGasLimit,
            .getBuilderBoostFactorFn = getBuilderBoostFactor,
            .setBuilderBoostFactorFn = setBuilderBoostFactor,
            .deleteBuilderBoostFactorFn = deleteBuilderBoostFactor,
            .getProposerConfigFn = getProposerConfig,
            .signVoluntaryExitFn = signVoluntaryExit,
        };
    }

    fn validateToken(ptr: *anyopaque, auth_header: ?[]const u8) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        if (self.auth) |auth| {
            try auth.validateRequest(auth_header);
        }
    }

    fn listKeys(ptr: *anyopaque, allocator: Allocator) ![]ValidatorKeyInfo {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        const infos = try self.client.validator_store.listLocalValidators(allocator);
        errdefer allocator.free(infos);

        const result = try allocator.alloc(ValidatorKeyInfo, infos.len);
        for (infos, result) |info, *out| {
            out.* = .{
                .pubkey = info.pubkey,
                .derivation_path = info.derivation_path,
                .readonly = info.readonly,
            };
        }
        allocator.free(infos);
        return result;
    }

    fn importKey(
        ptr: *anyopaque,
        allocator: Allocator,
        keystore_json: []const u8,
        password: []const u8,
        slashing_protection: ?[]const u8,
    ) ![]const u8 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;

        const secret_key = try keystore_mod.loadKeystore(allocator, keystore_json, password);
        const pubkey = secret_key.toPublicKey().compress();

        if (self.client.validator_store.signerKind(pubkey) != null) {
            return allocator.dupe(u8, "duplicate");
        }

        const persisted = try persisted_keys.writeKeystore(
            self.io,
            allocator,
            paths,
            pubkey,
            keystore_json,
            password,
            .{
                .hold_lock = true,
                .persist_if_duplicate = true,
            },
        );
        var held_lock = persisted.lock;
        errdefer if (held_lock) |*lock| lock.deinit(self.io);

        if (slashing_protection) |interchange_json| {
            importSlashingForPubkey(self.client, allocator, pubkey, interchange_json) catch |err| {
                _ = persisted_keys.deleteKeystore(self.io, allocator, paths, pubkey) catch {};
                return err;
            };
        }

        self.client.addLocalKeyRuntime(secret_key, held_lock) catch |err| {
            _ = persisted_keys.deleteKeystore(self.io, allocator, paths, pubkey) catch {};
            return err;
        };
        held_lock = null;

        return allocator.dupe(u8, "imported");
    }

    fn deleteKey(ptr: *anyopaque, allocator: Allocator, pubkey: [48]u8) !DeleteKeyResult {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;

        const slashing_json = try exportSlashingForPubkey(self.client, allocator, pubkey);
        errdefer allocator.free(slashing_json);

        const signer_kind = self.client.validator_store.signerKind(pubkey);
        const runtime_removed = if (signer_kind == .local)
            self.client.removeValidatorRuntime(pubkey) != null
        else
            false;
        const disk_deleted = try persisted_keys.deleteKeystore(self.io, allocator, paths, pubkey);

        const status_name: []const u8 = if (signer_kind == .local)
            (if (runtime_removed or disk_deleted) "deleted" else "not_active")
        else if (signer_kind == .remote)
            "not_active"
        else if (disk_deleted)
            "deleted"
        else if (std.mem.eql(u8, slashing_json, "{}"))
            "not_found"
        else
            "not_active";

        const status = try allocator.dupe(u8, status_name);
        errdefer allocator.free(status);

        return .{
            .status = status,
            .slashing_protection = slashing_json,
        };
    }

    fn listRemoteKeys(ptr: *anyopaque, allocator: Allocator) ![]RemoteKeyInfo {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        const infos = try self.client.validator_store.listRemoteValidators(allocator);
        errdefer allocator.free(infos);

        const result = try allocator.alloc(RemoteKeyInfo, infos.len);
        for (infos, result) |info, *out| {
            out.* = .{
                .pubkey = info.pubkey,
                .url = info.url,
                .readonly = info.readonly,
            };
        }
        allocator.free(infos);
        return result;
    }

    fn importRemoteKey(
        ptr: *anyopaque,
        allocator: Allocator,
        pubkey: [48]u8,
        url: []const u8,
    ) ![]const u8 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;

        try startup_signers.validateRemoteSignerUrl(url);

        if (self.client.validator_store.signerKind(pubkey) != null) {
            return allocator.dupe(u8, "duplicate");
        }

        _ = try persisted_keys.writeRemoteKey(self.io, allocator, paths, pubkey, url, true);
        self.client.addRemoteKeyRuntime(pubkey, url) catch |err| {
            _ = persisted_keys.deleteRemoteKey(self.io, allocator, paths, pubkey) catch {};
            return err;
        };
        return allocator.dupe(u8, "imported");
    }

    fn deleteRemoteKey(ptr: *anyopaque, allocator: Allocator, pubkey: [48]u8) ![]const u8 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;

        const signer_kind = self.client.validator_store.signerKind(pubkey);
        const runtime_removed = if (signer_kind == .remote)
            self.client.removeValidatorRuntime(pubkey) != null
        else
            false;
        const disk_deleted = try persisted_keys.deleteRemoteKey(self.io, allocator, paths, pubkey);

        const status_name: []const u8 = if (signer_kind == .remote)
            (if (runtime_removed or disk_deleted) "deleted" else "not_active")
        else if (signer_kind == .local)
            "not_active"
        else if (disk_deleted)
            "deleted"
        else
            "not_found";

        return allocator.dupe(u8, status_name);
    }

    fn getFeeRecipient(ptr: *anyopaque, pubkey: [48]u8) ![20]u8 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.client.validator_store.getFeeRecipient(pubkey);
    }

    fn setFeeRecipient(ptr: *anyopaque, pubkey: [48]u8, fee_recipient: [20]u8) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.setFeeRecipient(pubkey, fee_recipient);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
        self.refreshProposerPolicies();
    }

    fn deleteFeeRecipient(ptr: *anyopaque, pubkey: [48]u8) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.deleteFeeRecipient(pubkey);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
        self.refreshProposerPolicies();
    }

    fn getGraffiti(ptr: *anyopaque, pubkey: [48]u8) ![32]u8 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.client.validator_store.getGraffiti(pubkey);
    }

    fn setGraffiti(ptr: *anyopaque, pubkey: [48]u8, graffiti: [32]u8) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.setGraffiti(pubkey, graffiti);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
    }

    fn deleteGraffiti(ptr: *anyopaque, pubkey: [48]u8) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.deleteGraffiti(pubkey);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
    }

    fn getGasLimit(ptr: *anyopaque, pubkey: [48]u8) !u64 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.client.validator_store.getGasLimit(pubkey);
    }

    fn setGasLimit(ptr: *anyopaque, pubkey: [48]u8, gas_limit: u64) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.setGasLimit(pubkey, gas_limit);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
        self.refreshProposerPolicies();
    }

    fn deleteGasLimit(ptr: *anyopaque, pubkey: [48]u8) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.deleteGasLimit(pubkey);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
        self.refreshProposerPolicies();
    }

    fn getBuilderBoostFactor(ptr: *anyopaque, pubkey: [48]u8) !u64 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.client.validator_store.getBuilderBoostFactor(pubkey) orelse
            error.BuilderBoostFactorDisabled;
    }

    fn setBuilderBoostFactor(ptr: *anyopaque, pubkey: [48]u8, builder_boost_factor: u64) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.setBuilderBoostFactor(pubkey, builder_boost_factor);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
    }

    fn deleteBuilderBoostFactor(ptr: *anyopaque, pubkey: [48]u8) !void {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureProposerConfigWritable();
        const paths = self.client.config.persistence orelse return error.KeymanagerDisabled;
        try self.ensureKnownPubkey(pubkey);
        const previous = self.client.validator_store.getProposerConfig(pubkey);
        try self.client.validator_store.deleteBuilderBoostFactor(pubkey);
        self.persistProposerConfig(paths, pubkey, previous) catch |err| return err;
    }

    fn getProposerConfig(ptr: *anyopaque, allocator: Allocator, pubkey: [48]u8) ![]const u8 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        const config = self.client.validator_store.getProposerConfig(pubkey) orelse
            return allocator.dupe(u8, "null");
        return persisted_keys.serializeProposerConfig(allocator, config);
    }

    fn signVoluntaryExit(
        ptr: *anyopaque,
        allocator: Allocator,
        pubkey: [48]u8,
        epoch: ?u64,
    ) ![]const u8 {
        const self: *KeymanagerRuntime = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);

        const exit_epoch = epoch orelse self.client.clock.currentEpoch(self.io);
        const validator_index = self.client.validator_store.getValidatorIndex(pubkey) orelse
            return error.ValidatorNotFound;

        var signing_root: [32]u8 = undefined;
        const voluntary_exit = consensus_types.phase0.VoluntaryExit.Type{
            .epoch = exit_epoch,
            .validator_index = validator_index,
        };
        try signing.voluntaryExitSigningRoot(
            self.client.signing_context,
            &voluntary_exit,
            exit_epoch,
            &signing_root,
        );

        const signature = try self.client.validator_store.signVoluntaryExit(self.io, pubkey, signing_root);
        const signature_hex = std.fmt.bytesToHex(&signature.compress(), .lower);

        return std.fmt.allocPrint(
            allocator,
            "{{\"message\":{{\"epoch\":\"{d}\",\"validator_index\":\"{d}\"}},\"signature\":\"0x{s}\"}}",
            .{ exit_epoch, validator_index, signature_hex },
        );
    }

    fn ensureKnownPubkey(self: *const KeymanagerRuntime, pubkey: [48]u8) !void {
        if (self.client.validator_store.signerKind(pubkey) == null) return error.ValidatorNotFound;
    }

    fn ensureProposerConfigWritable(self: *const KeymanagerRuntime) !void {
        if (!self.proposer_config_write_enabled) return error.ProposerConfigWriteDisabled;
    }

    fn persistProposerConfig(
        self: *KeymanagerRuntime,
        paths: validator_types.PersistencePaths,
        pubkey: [48]u8,
        previous: ?ProposerConfig,
    ) !void {
        const current = self.client.validator_store.getProposerConfig(pubkey);
        _ = persisted_keys.writeProposerConfig(self.io, self.allocator, paths, pubkey, current) catch |err| {
            try self.client.validator_store.setProposerConfigOverride(pubkey, previous);
            return err;
        };
    }

    fn refreshProposerPolicies(self: *KeymanagerRuntime) void {
        if (!self.client.running.load(.acquire)) return;
        const epoch = self.client.clock.currentEpoch(self.io);
        self.client.prepare_proposer.onEpoch(self.io, epoch);
        if (self.client.builder_registration) |*builder_registration| {
            builder_registration.onEpoch(self.io, epoch);
        }
    }
};

fn importSlashingForPubkey(
    client: *ValidatorClient,
    allocator: Allocator,
    pubkey: [48]u8,
    interchange_json: []const u8,
) !void {
    const records = try interchange_mod.importInterchangeVerified(
        allocator,
        interchange_json,
        client.config.genesis_validators_root,
    );
    defer interchange_mod.deinitInterchangeData(allocator, records);

    for (records) |record| {
        if (!std.mem.eql(u8, &record.pubkey, &pubkey)) continue;
        try client.validator_store.slashing_db.importHistory(record);
    }
}

fn exportSlashingForPubkey(
    client: *ValidatorClient,
    allocator: Allocator,
    pubkey: [48]u8,
) ![]const u8 {
    const history = try client.validator_store.slashing_db.exportHistory(allocator, pubkey) orelse
        return interchange_mod.exportInterchange(allocator, &.{}, client.config.genesis_validators_root);
    defer {
        allocator.free(history.signed_blocks);
        allocator.free(history.signed_attestations);
    }

    const records = [_]validator_types.SlashingProtectionHistory{history};
    return interchange_mod.exportInterchange(allocator, &records, client.config.genesis_validators_root);
}
