#include <stdint.h>
#include <string.h>

/*
 * Performs a Skein1024 bit hash on a char array.  Example usage:
 * char *data = "hello world!";
 * uint8_t hashbuffer[128]; // buffer is always 1024 bits
 * HashCompact1024(data, strlen(data), hashbuffer);
 *
 * The algorithm processes the message in blocks (chunks of 1024 bits).
 */
void HashSkein1024(const uint8_t *msg, size_t msgByteCnt, uint8_t *hashVal);