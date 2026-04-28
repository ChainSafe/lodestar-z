const js = @import("zapi:zapi").js;
const stInnerShuffleList = @import("state_transition").shuffle.innerShuffleList;

pub fn innerShuffleList(list: js.Uint32Array, seed: js.Uint8Array, rounds: js.Number, forwards: js.Boolean) !void {
    const list_u32 = try list.toSlice();
    const seed_slice = try seed.toSlice();

    const rounds_i32 = rounds.assertI32();
    if (rounds_i32 < 0) return error.InvalidRoundsSize;
    if (rounds_i32 > 255) return error.InvalidRoundsSize;

    const rounds_u8: u8 = @intCast(rounds_i32);
    const is_forwards = forwards.assertBool();

    try stInnerShuffleList(u32, list_u32, seed_slice, rounds_u8, is_forwards);
}
