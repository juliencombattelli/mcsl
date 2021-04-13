#ifndef STRING_VIEW_FUZZY_TEST_HPP_
#define STRING_VIEW_FUZZY_TEST_HPP_

#include <mcsl/string_view.h>

#include <fuzzer/FuzzedDataProvider.h>

#include <fmt/ranges.h>

#include <stdexcept>
#include <string_view>

#define FWD(a) std::forward<decltype(a)>(a)

namespace sv {
namespace detail {

template <typename... TInputs>
constexpr bool input_provided(TInputs&&... inputs)
{
    if constexpr (sizeof...(inputs) == 0) {
        return false;
    } else {
        return true;
    }
}

template <typename TInput>
void log_input(fmt::memory_buffer& logbuffer, TInput&& input)
{
    fmt::format_to(logbuffer, "\t'{}' : '{}'\n", input.first, input.second);
}

template <typename... TInputs>
void log_inputs(fmt::memory_buffer& logbuffer, TInputs&&... inputs)
{
    fmt::format_to(logbuffer, "Inputs was:\n");
    (log_input(logbuffer, FWD(inputs)), ...);
}

} // namespace detail

/**
 * @brief Compare the results of an operation done with C's string_view and std::string_view
 * 
 * @param result_sv The result of the operation done with C's string_view
 * @param result_std_sv The result of the operation done with std::string_view
 * @param inputs Optional inputs to log, must be compatible with std::pair<std::string_view, T> (see AS_INPUT macro)
 */
template <typename TResult, typename... TInputs>
void assert_eq(const TResult result_sv, const TResult result_std_sv, TInputs&&... inputs)
{
    if (result_sv != result_std_sv) {
        fmt::memory_buffer logbuffer;
        fmt::format_to(logbuffer, "\nResults not matching.\n");
        fmt::format_to(logbuffer, "\tExpecting: '{}'\n", result_std_sv);
        fmt::format_to(logbuffer, "\tGot:       '{}'\n", result_sv);
        if (detail::input_provided(FWD(inputs)...)) {
            detail::log_inputs(logbuffer, FWD(inputs)...);
        }
        throw std::runtime_error { logbuffer.data() };
    }
}

/**
 * @brief Construct a C's string_view from a std::string_view
 */
mcsl_sv make_sv(std::string_view str) {
    return mcsl_sv_make_from_buffer(str.data(), str.size());
}

} // namespace sv

/**
 * @brief Construct from an input an object with a compatible type for use with assert_eq function
 * 
 * Concretely form a std::pair from an input stringified as a std::string_view for the first element,
 * and from a copy of the input for the second one.
 * 
 * @param input The input to construct the std::pair from
 */
#define AS_INPUT(input) (std::make_pair(std::string_view(#input), input))

#endif // STRING_VIEW_FUZZY_TEST_HPP_