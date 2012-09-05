#ifndef KERNEL_MEMORY_H
#define KERNEL_MEMORY_H

#define KERNEL_MEMORY_DEVNAME_LEN_MAX 64

typedef enum { KERNEL_MEMORY_MMAP, KERNEL_MEMORY_SHM } kernel_memory_type;

struct kernel_memory_shm
{
	key_t key;
	int id;
};
typedef struct kernel_memory_shm kernel_memory_shm_t;

struct kernel_memory_mmap
{
	char device_name[KERNEL_MEMORY_DEVNAME_LEN_MAX];
};
typedef struct kernel_memory_mmap kernel_memory_mmap_t;

struct kernel_memory
{
	kernel_memory_type type;
	size_t size;
	void *addr;
	union {
		kernel_memory_shm_t shm;
		kernel_memory_mmap_t mmap;
	} src;
};

typedef struct kernel_memory kernel_memory_t;

typedef void *(*kernel_memory_alloc_t)(size_t *,kernel_memory_t *);
typedef void (*kernel_memory_free_t)(kernel_memory_t *);

#endif
