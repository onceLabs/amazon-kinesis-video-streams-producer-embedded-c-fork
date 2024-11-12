

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>


#include "kvs/zephyr_fixes.h"

LOG_MODULE_REGISTER(zephyr_fixes, LOG_LEVEL_DBG);

void *k_realloc(void *ptr, size_t new_size) {
    if (ptr == NULL) {
        return k_malloc(new_size);
    }

    if (new_size == 0) {
        k_free(ptr);
        return NULL;
    }

    void *new_ptr = k_malloc(new_size);
    if (new_ptr == NULL) {
        return NULL;
    }

    // Copy the old data to the new block of memory
    memcpy(new_ptr, ptr, new_size);
    k_free(ptr);

    return new_ptr;
}