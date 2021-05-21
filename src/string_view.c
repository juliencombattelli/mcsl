#include <mcsl/string_view.h>

#include "char_traits.h"

#define SV_MIN(a, b) (((a) < (b)) ? (a) : (b))

mcsl_sv mcsl_sv_make_empty()
{
    return (mcsl_sv) { .data = NULL, .size = 0 };
}

mcsl_sv mcsl_sv_make_from_c_str(const char* str)
{
    if (str == NULL) {
        return mcsl_sv_make_empty();
    }
    return (mcsl_sv) { .data = str, .size = mcsl_length(str) };
}

mcsl_sv mcsl_sv_make_from_buffer(const char* buffer, size_t size)
{
    if (buffer == NULL) {
        return mcsl_sv_make_empty();
    }
    return (mcsl_sv) { .data = buffer, .size = size };
}

const char* mcsl_sv_data(mcsl_sv str)
{
    return str.data;
}

size_t mcsl_sv_size(mcsl_sv str)
{
    return str.size;
}

size_t mcsl_sv_length(mcsl_sv str)
{
    return str.size;
}

char mcsl_sv_at(mcsl_sv str, size_t index)
{
    return str.data[index];
}

const char* mcsl_sv_front(mcsl_sv str)
{
    return &str.data[0];
}

const char* mcsl_sv_back(mcsl_sv str)
{
    return &str.data[str.size - 1];
}

bool mcsl_sv_empty(mcsl_sv str)
{
    return str.size == 0;
}

mcsl_sv mcsl_sv_remove_prefix(mcsl_sv str, size_t n)
{
    str.data += n;
    str.size -= n;
    return str;
}

mcsl_sv mcsl_sv_remove_suffix(mcsl_sv str, size_t n)
{
    str.size -= n;
    return str;
}

mcsl_sv mcsl_sv_substr(mcsl_sv str, size_t pos, size_t n)
{
    return mcsl_sv_make_from_buffer(&str.data[pos], SV_MIN(n, str.size - pos));
}

int mcsl_sv_compare(mcsl_sv str1, mcsl_sv str2)
{
    const int res = mcsl_compare(str1.data, str2.data, SV_MIN(str1.size, str2.size));
    if (res == 0) {
        return str1.size - str2.size;
    }
    return res;
}

bool mcsl_sv_are_equal(mcsl_sv str1, mcsl_sv str2)
{
    return mcsl_sv_compare(str1, str2) == 0;
}

bool mcsl_sv_is_lesser_than(mcsl_sv str1, mcsl_sv str2)
{
    return mcsl_sv_compare(str1, str2) < 0;
}

bool mcsl_sv_is_greater_than(mcsl_sv str1, mcsl_sv str2)
{
    return mcsl_sv_compare(str1, str2) > 0;
}

bool mcsl_sv_starts_with(mcsl_sv str, mcsl_sv prefix)
{
    return mcsl_sv_are_equal(mcsl_sv_substr(str, 0, prefix.size), str);
}

bool mcsl_sv_starts_with_char(mcsl_sv str, char prefix)
{
    return str.data[0] == prefix;
}

bool mcsl_sv_ends_with(mcsl_sv str, mcsl_sv suffix)
{
    return str.size >= suffix.size
        && mcsl_sv_are_equal(
            mcsl_sv_substr(str, str.size - suffix.size, mcsl_npos),
            suffix);
}

bool mcsl_sv_ends_with_char(mcsl_sv str, char suffix)
{
    return !mcsl_sv_empty(str) && *mcsl_sv_back(str) == suffix;
}

bool mcsl_sv_contains(mcsl_sv str, mcsl_sv contained)
{
    return mcsl_sv_find(str, contained) != mcsl_npos;
}

size_t mcsl_sv_find_from_position(mcsl_sv str, size_t pos, mcsl_sv substr)
{
    if (substr.size == 0) {
        return pos <= str.size ? pos : mcsl_npos;
    }
    if (substr.size <= str.size) {
        while (pos <= str.size - substr.size) {
            if (str.data[pos] == substr.data[0]
                && mcsl_compare(str.data + pos + 1, substr.data + 1, substr.size - 1) == 0) {
                return pos;
            }
            ++pos;
        }
    }
    return mcsl_npos;
}

size_t mcsl_sv_find_char_from_position(mcsl_sv str, size_t pos, char c)
{
    size_t res = mcsl_npos;
    if (pos < str.size) {
        const size_t n = str.size - pos;
        const char* p = mcsl_find(str.data + pos, n, c);
        if (p) {
            res = p - str.data;
        }
    }
    return res;
}

size_t mcsl_sv_find(mcsl_sv str, mcsl_sv substr)
{
    return mcsl_sv_find_from_position(str, 0, substr);
}

size_t mcsl_sv_rfind_from_position(mcsl_sv str, size_t pos, mcsl_sv substr)
{
    if (substr.size <= str.size) {
        pos = SV_MIN(str.size - substr.size, pos);
        do {
            if (mcsl_compare(str.data + pos, substr.data, substr.size) == 0) {
                return pos;
            }
        } while (pos-- > 0);
    }
    return mcsl_npos;
}

size_t mcsl_sv_rfind(mcsl_sv str, mcsl_sv substr)
{
    return mcsl_sv_rfind_from_position(str, mcsl_npos, substr);
}

size_t mcsl_sv_find_first_of(mcsl_sv str, mcsl_sv chars)
{
    if (chars.size == 0) {
        return mcsl_npos;
    }
    for (size_t pos = 0; pos < str.size; ++pos) {
        for (size_t charpos = 0; charpos < chars.size; ++charpos) {
            if (str.data[pos] == chars.data[charpos]) {
                return pos;
            }
        }
    }
    return mcsl_npos;
}

size_t mcsl_sv_find_first_not_of(mcsl_sv str, mcsl_sv chars)
{
    if (chars.size == 0) {
        return 0;
    }
    for (size_t pos = 0; pos < str.size; ++pos) {
        for (size_t charpos = 0; charpos < chars.size; ++charpos) {
            if (str.data[pos] != chars.data[charpos]) {
                return pos;
            }
        }
    }
    return mcsl_npos;
}

size_t mcsl_sv_find_last_of(mcsl_sv str, mcsl_sv chars)
{
    if (chars.size == 0) {
        return mcsl_npos;
    }
    const char* const beg = str.data + str.size - 1;
    const char* const end = str.data - 1;
    for (const char* s = beg; s != end; --s) {
        for (size_t charpos = 0; charpos < chars.size; ++charpos) {
            if (*s == chars.data[charpos]) {
                return s - str.data;
            }
        }
    }
    return mcsl_npos;
}

size_t mcsl_sv_find_last_not_of(mcsl_sv str, mcsl_sv chars)
{
    if (chars.size == 0) {
        return mcsl_npos;
    }
    const char* const beg = str.data + str.size - 1;
    const char* const end = str.data - 1;
    for (const char* s = beg; s != end; --s) {
        for (size_t charpos = 0; charpos < chars.size; ++charpos) {
            if (*s != chars.data[charpos]) {
                return s - str.data;
            }
        }
    }
    return mcsl_npos;
}