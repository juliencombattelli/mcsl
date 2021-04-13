#include <string_view_fuzzy_test.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fuzzed_data(data, size);
    auto pos = fuzzed_data.ConsumeIntegral<size_t>();
    auto substr = fuzzed_data.ConsumeRandomLengthString(8);
    auto str = fuzzed_data.ConsumeRemainingBytesAsString();

    size_t index_sv = mcsl_sv_rfind_from_position(sv::make_sv(str), pos, sv::make_sv(substr));

    size_t index_stdsv = std::string_view { str }.rfind(substr, pos);

    sv::assert_eq(index_sv, index_stdsv,
        AS_INPUT(str),
        AS_INPUT(pos),
        AS_INPUT(substr));

    return 0;
}
