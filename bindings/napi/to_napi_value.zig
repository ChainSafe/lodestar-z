const ssz = @import("ssz");
const napi = @import("zapi:napi");

pub fn sszValueToNapiValue(env: napi.Env, comptime ST: type, value: *const ST.Type) !napi.Value {
    switch (ST.kind) {
        .uint => {
            return try env.createInt64(@intCast(value.*));
        },
        .bool => {
            return try env.getBoolean(value.*);
        },
        .vector => {
            if (comptime ssz.isByteVectorType(ST)) {
                var bytes: [*]u8 = undefined;
                const buf = try env.createArrayBuffer(ST.length, &bytes);
                @memcpy(bytes[0..ST.length], value);
                return try env.createTypedarray(.uint8, ST.length, buf, 0);
            } else {
                const arr = try env.createArrayWithLength(ST.length);
                for (value, 0..) |*v, i| {
                    const napi_element = try sszValueToNapiValue(env, ST.Element, v);
                    try arr.setElement(@intCast(i), napi_element);
                }
                return arr;
            }
        },
        .list => {
            if (comptime ssz.isByteListType(ST)) {
                var bytes: [*]u8 = undefined;
                const buf = try env.createArrayBuffer(value.items.len, &bytes);
                @memcpy(bytes[0..value.items.len], value.items);
                return try env.createTypedarray(.uint8, value.items.len, buf, 0);
            } else {
                const arr = try env.createArrayWithLength(value.items.len);
                for (value.items, 0..) |*v, i| {
                    const napi_element = try sszValueToNapiValue(env, ST.Element, v);
                    try arr.setElement(@intCast(i), napi_element);
                }
                return arr;
            }
        },
        .container => {
            const obj = try env.createObject();
            inline for (ST.fields) |field| {
                const field_value = &@field(value, field.name);
                const napi_field_value = try sszValueToNapiValue(env, field.type, field_value);
                try obj.setNamedProperty(field.name, napi_field_value);
            }
            return obj;
        },
    }
}

const NumberSliceOpts = struct {
    typed_array: ?napi.value_types.TypedarrayType = null,
};

pub fn numberSliceToNapiValue(
    env: napi.Env,
    comptime T: type,
    numbers: []const T,
    comptime opts: NumberSliceOpts,
) !napi.Value {
    if (opts.typed_array) |typed_array_type| {
        var bytes: [*]u8 = undefined;
        const bytes_len = numbers.len * typed_array_type.elementSize();
        const buf = try env.createArrayBuffer(bytes_len, &bytes);
        if (T == typed_array_type.elementType()) {
            @memcpy(bytes[0..bytes_len], @as([]const u8, @ptrCast(numbers)));
        } else {
            var bytes_numbers: []T = @ptrCast(bytes[0..bytes_len]);
            for (numbers, 0..) |num, i| {
                bytes_numbers[i] = @intCast(num);
            }
        }
        return try env.createTypedarray(typed_array_type, numbers.len, buf, 0);
    } else {
        const arr = try env.createArrayWithLength(numbers.len);
        for (numbers, 0..) |num, i| {
            const napi_element = try env.createInt64(@intCast(num));
            try arr.setElement(@intCast(i), napi_element);
        }
        return arr;
    }
}
