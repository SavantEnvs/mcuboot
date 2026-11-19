#include <stdint.h>
int base64_encode(const void *, int, char *, uint8_t);
int base64_decode(const char *, void *);
int base64_decode_len(const char *str);
#define BASE64_ENCODE_SIZE(__size) (((((__size) - 1) / 3) * 4) + 4)
