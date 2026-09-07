const std = @import("std");
const napi = @import("zapi:zapi").napi;
const js = @import("zapi:zapi").js;
const active_preset = @import("preset").active_preset;
const c = @import("config");
const BeaconConfig = @import("config").BeaconConfig;
const ChainConfig = @import("config").ChainConfig;
const Preset = @import("preset").Preset;

const max_blob_schedule_entries = 16;

const State = struct {
    config: BeaconConfig = undefined,
    initialized: bool = false,
    config_name: [64]u8 = undefined,
    blob_schedule: [max_blob_schedule_entries]ChainConfig.BlobScheduleEntry =
        [_]ChainConfig.BlobScheduleEntry{.{
            .EPOCH = 0,
            .MAX_BLOBS_PER_BLOCK = 0,
        }} ** max_blob_schedule_entries,

    pub fn init(self: *State) void {
        if (self.initialized) return;

        switch (active_preset) {
            .mainnet => self.config = c.mainnet.config,
            .minimal => self.config = c.minimal.config,
            .gnosis => self.config = c.chiado.config,
        }
        self.initialized = true;
    }

    pub fn deinit(self: *State) void {
        if (!self.initialized) return;

        self.initialized = false;
    }
};

pub var state: State = .{};

fn valueToU64(value: napi.Value) !u64 {
    const num = try value.getValueDouble();
    if (std.math.isPositiveInf(num)) {
        return std.math.maxInt(u64);
    }
    if (!std.math.isFinite(num) or num < 0 or num > @as(f64, @floatFromInt(std.math.maxInt(u64)))) {
        return error.InvalidChainConfigFieldValue;
    }
    return @intFromFloat(num);
}

/// JS: config.set(chainConfigObj, genesisValidatorsRoot)
pub fn set(object: js.Value, genesis_root: js.Uint8Array) !void {
    if (!state.initialized) {
        return error.ConfigNotInitialized;
    }

    const chain_config = try chainConfigFromObject(js.env(), try object.toValue().coerceToObject());

    const root_slice = try genesis_root.toSlice();
    if (root_slice.len != 32) {
        return error.InvalidGenesisValidatorsRootLength;
    }

    state.config = BeaconConfig.init(
        chain_config,
        root_slice[0..32].*,
    );

    state.initialized = true;
}

fn chainConfigFromObject(env: napi.Env, obj: napi.Value) !ChainConfig {
    var chain_config: ChainConfig = undefined;

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
                    _ = try field_value.getValueStringUtf8(&state.config_name);
                    if (comptime std.mem.eql(u8, field.name, "CONFIG_NAME")) {
                        @field(chain_config, field.name) = &state.config_name;
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
                        state.blob_schedule[i] = blob_schedule_entry;
                    }
                    @field(chain_config, field.name) = state.blob_schedule[0..array_length];
                },
                else => return error.UnsupportedChainConfigFieldType,
            }
        }
    }
    return chain_config;
}
