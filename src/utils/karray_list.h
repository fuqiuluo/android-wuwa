#ifndef ANDROID_WUWA_KARRAY_LIST_H
#define ANDROID_WUWA_KARRAY_LIST_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/version.h>

#define ARRAYLIST_DEFAULT_CAPACITY 16

struct karray_list {
    void** data;
    size_t size;
    size_t capacity;
};

struct karray_list* arraylist_create(size_t initial_capacity);
void arraylist_destroy(struct karray_list* list);
void* arraylist_remove(struct karray_list* list, size_t index);
void* arraylist_get(struct karray_list* list, size_t index);
int arraylist_add(struct karray_list* list, void* element);
void arraylist_clear(struct karray_list* list);

#endif // ANDROID_WUWA_KARRAY_LIST_H
