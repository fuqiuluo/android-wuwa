#include "karray_list.h"

#include <linux/errno.h>
#include <linux/hugetlb.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

struct karray_list* arraylist_create(size_t initial_capacity) {
    struct karray_list* list = kmalloc(sizeof(*list), GFP_KERNEL);
    if (!list)
        return NULL;

    if (initial_capacity < ARRAYLIST_DEFAULT_CAPACITY)
        initial_capacity = ARRAYLIST_DEFAULT_CAPACITY;

    list->data = kmalloc_array(initial_capacity, sizeof(void*), GFP_KERNEL);
    if (!list->data) {
        kfree(list);
        return NULL;
    }

    list->size = 0;
    list->capacity = initial_capacity;
    return list;
}

static int ensure_capacity(struct karray_list* list, size_t min_capacity) {
    if (min_capacity <= list->capacity)
        return 0;

    size_t new_capacity = list->capacity + (list->capacity >> 1);
    if (new_capacity < min_capacity)
        new_capacity = min_capacity;

    void** new_data = krealloc_array(list->data, new_capacity, sizeof(void*), GFP_KERNEL);
    if (!new_data)
        return -ENOMEM;

    list->data = new_data;
    list->capacity = new_capacity;
    return 0;
}

int arraylist_add(struct karray_list* list, void* element) {
    int ret = 0;

    if (ensure_capacity(list, list->size + 1)) {
        ret = -ENOMEM;
        goto out;
    }

    list->data[list->size++] = element;

    out:
        return ret;
}

void* arraylist_get(struct karray_list* list, size_t index) {
    void* element = NULL;

    if (index < list->size)
        element = list->data[index];
    return element;
}

void* arraylist_remove(struct karray_list* list, size_t index) {
    void* element = NULL;

    if (index >= list->size)
        goto out;

    element = list->data[index];
    memmove(&list->data[index], &list->data[index + 1], (list->size - index - 1) * sizeof(void*));
    list->size--;

    out:
        return element;
}

void arraylist_clear(struct karray_list* list) {
    list->size = 0;
}

void arraylist_destroy(struct karray_list* list) {
    if (list->data)
        kfree(list->data);
    kfree(list);
}