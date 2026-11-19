#include <stdint.h>
#include <stddef.h>
#define CRC16_INITIAL_CRC 0
uint16_t crc16_ccitt(uint16_t initial_crc, const void *buf, int len);
