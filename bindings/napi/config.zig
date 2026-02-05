const std = @import("std");
const napi = @import("zapi:napi");
const active_preset = @import("preset").active_preset;
const c = @import("config");
const BeaconConfig = @import("config").BeaconConfig;
const ChainConfig = @import("config").ChainConfig;

/// Allocator for internal allocations.
/// Creating ChainConfigs allocate memory for certain fields.
const allocator = std.heap.page_allocator;

/// A global config for N-API bindings to use.
pub var config: BeaconConfig = undefined;
var initialized: bool = false;

pub fn init() void {
    if (initialized) {
        return;
    }

    switch (active_preset) {
        .mainnet => {
            config = c.mainnet.config;
        },
        .minimal => {
            config = c.minimal.config;
        },
        .gnosis => {
            config = c.chiado.config;
        },
    }
}

pub fn Config_set(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    if (!initialized) {
        return error.ConfigNotInitialized;
    }

    const obj = try cb.arg(0).coerceToObject();
    const chain_config = try chainConfigFromObject(env, obj);
    const genesis_validators_root_info = try cb.arg(1).getTypedarrayInfo();
    if (genesis_validators_root_info.data.len != 32) {
        return error.InvalidGenesisValidatorsRootLength;
    }

    config = BeaconConfig.init(
        chain_config,
        genesis_validators_root_info.data[0..32].*,
    );

    initialized = true;

    return env.getUndefined();
}

pub fn deinit() void {
    if (!initialized) {
        return;
    }

    // Free any allocated fields in config here
    inline for (std.meta.fields(ChainConfig)) |field| {
        switch (field.type) {
            []const u8 => {
                const field_value = @field(config.chain, field.name);
                allocator.free(field_value);
            },
            []ChainConfig.BlobScheduleEntry => {
                const field_value = @field(config.chain, field.name);
                allocator.free(field_value);
            },
            else => {},
        }
    }

    initialized = false;
}

pub fn chainConfigFromObject(env: napi.Env, obj: napi.Value) !ChainConfig {
    var chain_config: ChainConfig = undefined;
    inline for (std.meta.fields(ChainConfig)) |field| {
        const field_value = obj.getNamedProperty(field.name) catch |err| {
            try env.throwError(@errorName(err), "Missing field " ++ field.name);
            return error.PendingException;
        };
        switch (field.type) {
            u64 => {
                const num = try field_value.getValueInt64();
                // TODO check for infinity
                @field(chain_config, field.name) = num;
            },
            u256 => {
                var sign_bit: u1 = 0;
                var words_buf: [4]u64 = undefined;
                const words = try field_value.getValueBigintWords(&sign_bit, &words_buf);
                if (sign_bit != 0) {
                    return error.InvalidChainConfigFieldValue;
                }
                var num_u256: u256 = 0;
                for (0..4) |i| {
                    num_u256 |= u256(words[i]) << (@as(u256, i) * 64);
                }
                @field(chain_config, field.name) = num_u256;
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
                var str_buf: [64]u8 = undefined;
                const str = try field_value.getValueStringUtf8(&str_buf);
                @field(chain_config, field.name) = try allocator.dupe(u8, str);
            },
            []ChainConfig.BlobScheduleEntry => {
                const array_length = try field_value.getArrayLength();
                const blob_schedule = try allocator.alloc(c.BlobScheduleEntry, array_length);
                errdefer allocator.free(blob_schedule);

                for (0..array_length) |i| {
                    const entry_value = try field_value.getElement(i);
                    const epoch_value = try entry_value.getNamedProperty("EPOCH");
                    const max_blobs_value = try entry_value.getNamedProperty("MAX_BLOBS_PER_BLOCK");

                    blob_schedule[i] = c.BlobScheduleEntry{
                        .EPOCH = try epoch_value.getValueUint64(),
                        .MAX_BLOBS_PER_BLOCK = try max_blobs_value.getValueUint64(),
                    };
                }
                @field(chain_config, field.name) = blob_schedule;
            },
            else => return error.UnsupportedChainConfigFieldType,
        }
    }
    return chain_config;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const config_obj = try env.createObject();
    try config_obj.setNamedProperty("set", try env.createFunction(
        "set",
        2,
        Config_set,
        null,
    ));

    try exports.setNamedProperty("config", config_obj);
}
