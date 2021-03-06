#ifndef MCSL_STRING_VIEW_H_
#define MCSL_STRING_VIEW_H_

#include <mcsl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mcsl_string_view {
    const char* data;
    size_t size;
} mcsl_sv;

mcsl_sv mcsl_sv_make_from_c_str(const char* str);

mcsl_sv mcsl_sv_make_from_buffer(const char* buffer, size_t size);

const char* mcsl_sv_data(mcsl_sv str);

size_t mcsl_sv_size(mcsl_sv str);

size_t mcsl_sv_length(mcsl_sv str);

char mcsl_sv_at(mcsl_sv str, size_t index);

const char* mcsl_sv_front(mcsl_sv str);

const char* mcsl_sv_back(mcsl_sv str);

bool mcsl_sv_empty(mcsl_sv str);

mcsl_sv mcsl_sv_remove_prefix(mcsl_sv str, size_t n);

mcsl_sv mcsl_sv_remove_suffix(mcsl_sv str, size_t n);

mcsl_sv mcsl_sv_substr(mcsl_sv str, size_t pos, size_t n);

int mcsl_sv_compare(mcsl_sv str1, mcsl_sv str2);

bool mcsl_sv_are_equal(mcsl_sv str1, mcsl_sv str2);

bool mcsl_sv_is_lesser_than(mcsl_sv str1, mcsl_sv str2);

bool mcsl_sv_is_lesser_or_equal_than(mcsl_sv str1, mcsl_sv str2);

bool mcsl_sv_is_greater_than(mcsl_sv str1, mcsl_sv str2);

bool mcsl_sv_is_greater_or_equal_than(mcsl_sv str1, mcsl_sv str2);

bool mcsl_sv_starts_with(mcsl_sv str, mcsl_sv prefix);

bool mcsl_sv_starts_with_char(mcsl_sv str, char prefix);

bool mcsl_sv_ends_with(mcsl_sv str, mcsl_sv suffix);

bool mcsl_sv_ends_with_char(mcsl_sv str, char suffix);

bool mcsl_sv_contains(mcsl_sv str, mcsl_sv substr);

bool mcsl_sv_contains_char(mcsl_sv str, char c);

size_t mcsl_sv_find(mcsl_sv str, mcsl_sv substr);

size_t mcsl_sv_find_from_position(mcsl_sv str, size_t pos, mcsl_sv substr);

size_t mcsl_sv_find_char_from_position(mcsl_sv str, size_t pos, char c);

size_t mcsl_sv_rfind(mcsl_sv str, mcsl_sv substr);

size_t mcsl_sv_rfind_from_position(mcsl_sv str, size_t pos, mcsl_sv substr);

size_t mcsl_sv_rfind_char_from_position(mcsl_sv str, size_t pos, char c);

size_t mcsl_sv_find_first_of(mcsl_sv str, mcsl_sv chars);

size_t mcsl_sv_find_first_char(mcsl_sv str, char c);

size_t mcsl_sv_find_first_not_of(mcsl_sv str, mcsl_sv chars);

size_t mcsl_sv_find_first_char_different(mcsl_sv str, char c);

size_t mcsl_sv_find_last_of(mcsl_sv str, mcsl_sv chars);

size_t mcsl_sv_find_last_char(mcsl_sv str, char c);

size_t mcsl_sv_find_last_not_of(mcsl_sv str, mcsl_sv chars);

size_t mcsl_sv_find_last_char_different(mcsl_sv str, char c);

typedef struct mcsl_string_view_split_result {
    size_t count;
    size_t stop;
} mcsl_sv_split_result;

mcsl_sv_split_result mcsl_sv_split(mcsl_sv sv, mcsl_sv delims, mcsl_sv result[], size_t result_size);

mcsl_sv_split_result mcsl_sv_split_compressed(mcsl_sv sv, mcsl_sv delims, mcsl_sv result[], size_t result_size);

#ifdef __cplusplus
}
#endif

#endif // MCSL_STRING_VIEW_H_