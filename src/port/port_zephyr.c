/**
 * @file port_zephyr.c
 * @brief Implementation of the platform specific functionality for Zephyr
 * 
 * @author Andrew Nyland
 * @date 9/16/24
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "kvs/errors.h"
#include "kvs/port.h"

#include <zephyr/random/random.h>

#define PAST_OLD_TIME_IN_EPOCH 1600000000

int platformInit(void)
{
    int res = KVS_ERRNO_NONE;

    // srand(time(NULL)); Zephyr doesn't init rand()?

    return res;
}

int getTimeInIso8601(char *pBuf, size_t uBufSize)
{
    int res = KVS_ERRNO_NONE;
    time_t xTimeUtcNow = {0};

    if (pBuf == NULL || uBufSize < DATE_TIME_ISO_8601_FORMAT_STRING_SIZE)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        xTimeUtcNow = time(NULL);
        /* Current time should not less than a specific old time. If it does, then it means system time is incorrect. */
        if ((long)xTimeUtcNow < (long)PAST_OLD_TIME_IN_EPOCH)
        {
            res = KVS_ERROR_PAST_OLD_TIME;
        }
        else
        {
            strftime(pBuf, DATE_TIME_ISO_8601_FORMAT_STRING_SIZE, "%Y%m%dT%H%M%SZ", gmtime(&xTimeUtcNow));
        }
    }

    return res;
}

uint64_t getEpochTimestampInMs(void)
{
    uint64_t timestamp = 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    timestamp = (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;

    return timestamp;
}

uint8_t getRandomNumber(void)
{
    return (uint8_t)sys_rand32_get();
}

void sleepInMs(uint32_t ms)
{
    // usleep(ms * 1000);
    k_sleep(K_MSEC(ms));
}