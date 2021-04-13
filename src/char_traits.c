#include "char_traits.h"

#include <string.h>

size_t mcsl_length(const char* str)
{
    return strlen(str);
}

const char* mcsl_find(const char* str, size_t n, char c)
{
    if (n == 0) {
        return NULL;
    }
    return memchr(str, c, n);
}

int mcsl_compare(const char* str1, const char* str2, size_t n)
{
    if (n == 0) {
        return 0;
    }
    return memcmp(str1, str2, n);
}

char* mcsl_move(char* str1, const char* str2, size_t n)
{
    if (n == 0) {
        return str1;
    }
    return memmove(str1, str2, n);
}

char* mcsl_copy(char* str1, const char* str2, size_t n)
{
    if (n == 0) {
        return str1;
    }
    return memcpy(str1, str2, n);
}

char* mcsl_assign(char* str, size_t n, char c)
{
    if (n == 0) {
        return str;
    }
    return memset(str, c, n);
}