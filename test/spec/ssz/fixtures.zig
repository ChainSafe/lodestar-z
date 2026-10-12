const spec_test_options = @import("spec_test_options");

pub const version = spec_test_options.ssz_spec_test_version;
pub const archive_name = "ssz-test-vectors-" ++ version;
pub const out_dir = spec_test_options.spec_test_out_dir ++ "/ssz";
pub const fixtures_dir = out_dir ++ "/" ++ version ++ "/" ++ archive_name ++ "/fixtures/ssz/ssz";
