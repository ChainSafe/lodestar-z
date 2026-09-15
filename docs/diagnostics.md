# Zig 错误详情

Diagnostics 保存当前一次调用的可选结构化详情。它只用于 Zig 层，目前接入 STF 的
withdrawals root 校验。原有错误码、校验顺序和 binding 行为保持不变。

```zig
var diagnostics: st.Diagnostics = .{};
const post_state = st.stateTransition(allocator, io, state, block, .{
    .diagnostics = &diagnostics,
}, null) catch |err| {
    if (diagnostics.detail) |*details| {
        std.log.err("{f}", .{details});
    }
    return err;
};
```

公共 `ErrorDetails` union 只按模块分类；各模块独立定义自己的 `ErrorDetails` union、具名诊断函数和格式化。
目前只有 state_transition 分支，未接入的模块不添加占位分支。

调用方确认两个 tag 后，可读取 `diagnostics.detail.?.state_transition.withdrawals_root_mismatch`
中的 expected 和 actual。
两者都是内联的 `[32]u8`，失败路径的临时 state 被释放后仍然有效。

校验点调用 `diagnostics.state_transition.withdrawalsRootMismatch(diag, expected, actual)`。函数写入详情，
然后返回原来的 `error.WithdrawalsRootMismatch`。不需要详情的调用方省略 options 字段，
直接调用 `processWithdrawals` 时传 null。

每次操作使用新的对象；复用时在调用前赋值 `diagnostics = .{};`。
没有额外详情的错误不写入对象。内部函数不重置调用方对象。

当前表示没有列表、容量状态、通用字段表、wrapper 或外层 slot 上下文，也不分配内存。
新增 STF 诊断只需扩展 STF 的 union 和具名函数；新增模块时在公共 union 加入该模块分支。
不为没有附加信息的错误创建空包装函数。
