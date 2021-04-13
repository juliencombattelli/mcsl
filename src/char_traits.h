#ifndef MCSL_CHAR_TRAITS_H_
#define MCSL_CHAR_TRAITS_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t mcsl_length(const char* str);
const char* mcsl_find(const char* str, size_t n, char c);
int mcsl_compare(const char* str1, const char* str2, size_t n);
char* mcsl_move(char* str1, const char* str2, size_t n);
char* mcsl_copy(char* str1, const char* str2, size_t n);
char* mcsl_assign(char* str, size_t n, char c);

#ifdef __cplusplus
}
#endif

#endif // MCSL_CHAR_TRAITS_H_