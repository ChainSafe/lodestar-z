const std = @import("std");
const napi = @import("zapi:zapi").napi;
const js = @import("zapi:zapi").js;
const active_preset = @import("preset").active_preset;
const c = @import("config");
const BeaconConfig = @import("config").BeaconConfig;
const ChainConfig = @import("config").ChainConfig;
const Preset = @import("preset").Preset;

const max_blob_schedule_entries = 16;

const allocator = std.heap.c_allocator;

pub const ConfigSnapshot = struct {
    config: BeaconConfig = undefined,
    config_name: [64]u8 = undefined,
    blob_schedule: [max_blob_schedule_entries]ChainConfig.BlobScheduleEntry = undefined,

    pub fn deinit(_: *ConfigSnapshot) void {}
};

pub const SnapshotRc = @import("state_transition").RefCount(ConfigSnapshot);

pub fn defaultConfig() BeaconConfig {
    return switch (active_preset) {
        .mainnet => c.mainnet.config,
        .minimal => c.minimal.config,
        .gnosis => c.chiado.config,
    };
}

pub fn createDefault() !*SnapshotRc {
    return SnapshotRc.init(allocator, .{ .config = defaultConfig() });
}

pub fn create(object: js.Value, genesis_root: js.Uint8Array) !*SnapshotRc {
    const root_slice = try genesis_root.toSlice();
    if (root_slice.len != 32) return error.InvalidGenesisValidatorsRootLength;

    const snapshot = try SnapshotRc.init(allocator, .{});
    errdefer snapshot.unref();

    const object_value = try object.toValue().coerceToObject();
    var chain_config = try chainConfigFromObject(
        &snapshot.instance,
        js.env(),
        object_value,
    );
    if (chain_config.PRESET_BASE != active_preset) return error.PresetMismatch;
    if (try (try object_value.getNamedProperty("SECONDS_PER_SLOT")).typeof() == .undefined) {
        if (chain_config.SLOT_DURATION_MS == 0 or chain_config.SLOT_DURATION_MS % 1000 != 0) {
            return error.InvalidSlotDuration;
        }
        chain_config.SECONDS_PER_SLOT = @divExact(chain_config.SLOT_DURATION_MS, 1000);
    } else if (try (try object_value.getNamedProperty("SLOT_DURATION_MS")).typeof() == .undefined) {
        chain_config.SLOT_DURATION_MS = std.math.mul(u64, chain_config.SECONDS_PER_SLOT, 1000) catch {
            return error.InvalidSlotDuration;
        };
    }
    if (chain_config.SECONDS_PER_SLOT == 0 or chain_config.SLOT_DURATION_MS % 1000 != 0 or
        chain_config.SECONDS_PER_SLOT != chain_config.SLOT_DURATION_MS / 1000)
    {
        return error.InvalidSlotDuration;
    }
    snapshot.instance.config = BeaconConfig.init(chain_config, root_slice[0..32].*);
    return snapshot;
}

fn valueToU64(value: napi.Value) !u64 {
    const num = try value.getValueDouble();
    if (std.math.isPositiveInf(num)) {
        return std.math.maxInt(u64);
    }
    if (!std.math.isFinite(num) or num != @floor(num) or num < 0 or num >= @as(f64, @floatFromInt(std.math.maxInt(u64)))) {
        return error.InvalidChainConfigFieldValue;
    }
    return @intFromFloat(num);
}

fn chainConfigFromObject(snapshot: *ConfigSnapshot, env: napi.Env, obj: napi.Value) !ChainConfig {
    var chain_config = defaultConfig().chain;

    inline for (std.meta.fields(ChainConfig)) |field| {
        const field_value: napi.Value = obj.getNamedProperty(field.name) catch |err| {
            try env.throwError(@errorName(err), "Missing field " ++ field.name);
            return error.PendingException;
        };

        if (try field_value.typeof() == .undefined) {
            std.log.debug("missing field value for: {s}, skipping\n", .{field.name});
        } else {
            switch (field.type) {
                Preset => {
                    var str_buf: [16]u8 = undefined;
                    const preset_str = try field_value.getValueStringUtf8(&str_buf);
                    @field(chain_config, field.name) =
                        if (std.mem.eql(u8, preset_str, "mainnet"))
                            .mainnet
                        else if (std.mem.eql(u8, preset_str, "minimal"))
                            .minimal
                        else if (std.mem.eql(u8, preset_str, "gnosis"))
                            .gnosis
                        else
                            return error.InvalidPreset;
                },
                u64 => @field(chain_config, field.name) = try valueToU64(field_value),
                u256 => {
                    var str_buf: [128]u8 = undefined;
                    const str = try (try field_value.coerceToString()).getValueStringUtf8(&str_buf);
                    @field(chain_config, field.name) = std.fmt.parseInt(u256, str, 10) catch {
                        return error.InvalidChainConfigFieldValue;
                    };
                },
                [4]u8 => {
                    const typedarray_info = try field_value.getTypedarrayInfo();
                    if (typedarray_info.data.len != 4) {
                        return error.InvalidVersionLength;
                    }
                    var version: [4]u8 = undefined;
                    @memcpy(&version, typedarray_info.data);
                    @field(chain_config, field.name) = version;
                },
                [20]u8 => {
                    const typedarray_info = try field_value.getTypedarrayInfo();
                    if (typedarray_info.data.len != 20) {
                        return error.InvalidAddressLength;
                    }
                    var address: [20]u8 = undefined;
                    @memcpy(&address, typedarray_info.data);
                    @field(chain_config, field.name) = address;
                },
                [32]u8 => {
                    const typedarray_info = try field_value.getTypedarrayInfo();
                    if (typedarray_info.data.len != 32) {
                        return error.InvalidRootLength;
                    }
                    var root: [32]u8 = undefined;
                    @memcpy(&root, typedarray_info.data);
                    @field(chain_config, field.name) = root;
                },
                []const u8 => {
                    const config_name = try field_value.getValueStringUtf8(&snapshot.config_name);
                    if (comptime std.mem.eql(u8, field.name, "CONFIG_NAME")) {
                        @field(chain_config, field.name) = config_name;
                    } else {
                        @compileError("unsupported field: " ++ field.name);
                    }
                },
                []const ChainConfig.BlobScheduleEntry => {
                    const array_length: usize = @intCast(try field_value.getArrayLength());
                    if (array_length > max_blob_schedule_entries) {
                        return error.BlobScheduleTooLong;
                    }

                    for (0..array_length) |i| {
                        const entry_value = try field_value.getElement(@intCast(i));
                        const epoch_value = try entry_value.getNamedProperty("EPOCH");
                        const max_blobs_value = try entry_value.getNamedProperty("MAX_BLOBS_PER_BLOCK");

                        const blob_schedule_entry = ChainConfig.BlobScheduleEntry{
                            .EPOCH = try valueToU64(epoch_value),
                            .MAX_BLOBS_PER_BLOCK = try valueToU64(max_blobs_value),
                        };
                        snapshot.blob_schedule[i] = blob_schedule_entry;
                    }
                    @field(chain_config, field.name) = snapshot.blob_schedule[0..array_length];
                },
                else => return error.UnsupportedChainConfigFieldType,
            }
        }
    }
    return chain_config;
}
