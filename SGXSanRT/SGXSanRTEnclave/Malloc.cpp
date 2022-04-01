
#include <unordered_set>
#include <pthread.h>
#include "SGXSanManifest.h"
#include "PoisonCheck.hpp"
#include "Malloc.hpp"
#include "SGXSanCommonPoison.hpp"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanRTEnclave.hpp"
#include "Quarantine.hpp"
#include "InternalDlmalloc.hpp"
#include "SGXSanPrintf.hpp"

#if (USE_SGXSAN_MALLOC)
#define MALLOC sgxsan_malloc
#define BACKEND_MALLOC malloc
#define FREE sgxsan_free
#define BACKEND_FREE free
#define CALLOC sgxsan_calloc
#define BACKEND_CALLOC calloc
#define REALLOC sgxsan_realloc
#define BACKEND_REALLOC realloc
#define MALLOC_USABLE_SZIE sgxsan_malloc_usable_size
#define BACKEND_MALLOC_USABLE_SZIE malloc_usable_size
#else
// fix-me: how about tcmalloc
#define MALLOC malloc
#define BACKEND_MALLOC dlmalloc
#define FREE free
#define BACKEND_FREE dlfree
#define CALLOC calloc
#define BACKEND_CALLOC dlcalloc
#define REALLOC realloc
#define BACKEND_REALLOC dlrealloc
#define MALLOC_USABLE_SZIE malloc_usable_size
#define BACKEND_MALLOC_USABLE_SZIE dlmalloc_usable_size
#endif

/* The maximum possible size_t value has all bits set */
#define MAX_SIZE_T (~(size_t)0)

__thread bool is_in_heap_operator_wrapper = false;

struct chunk
{
	uptr alloc_beg;
	size_t user_size;
};

void *MALLOC(size_t size)
{
	// PRINTF("\n[malloc] is_in_heap_operator_wrapper=%d\n", is_in_heap_operator_wrapper);
	if (not asan_inited || is_in_heap_operator_wrapper)
	{
		return BACKEND_MALLOC(size);
	}
	// if (size == 0)
	// {
	// 	return nullptr;
	// }
	is_in_heap_operator_wrapper = true;

	uptr alignment = SHADOW_GRANULARITY;

	uptr rz_size = ComputeRZSize(size);
	uptr rounded_size = RoundUpTo(size, alignment);
	uptr needed_size = rounded_size + 2 * rz_size;

	void *allocated = BACKEND_MALLOC(needed_size);

	size_t allocated_size = BACKEND_MALLOC_USABLE_SZIE(allocated);
	needed_size = allocated_size;

	if (allocated == nullptr)
	{
		is_in_heap_operator_wrapper = false;
		return nullptr;
	}

	uptr alloc_beg = reinterpret_cast<uptr>(allocated);
	// If dlmalloc doesn't return an aligned memory, it's troublesome.
	// If it is so, we start to posion from RoundUpTo(allocated)
	assert(IsAligned(alloc_beg, alignment) && "here I want to see whether dlmalloc return an unaligned memory");
	uptr alloc_end = alloc_beg + needed_size;

	uptr user_beg = alloc_beg + rz_size;
	if (!IsAligned(user_beg, alignment))
		user_beg = RoundUpTo(user_beg, alignment);
	uptr user_end = user_beg + size;
	CHECK_LE(user_end, alloc_end);

	// place the chunk in left redzone
	uptr chunk_beg = user_beg - sizeof(chunk);
	chunk *m = reinterpret_cast<chunk *>(chunk_beg);

	// if alloc_beg is not aligned, we cannot automatically calculate it
	m->alloc_beg = alloc_beg;
	m->user_size = size;

	// PRINTF("\n[Malloc] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", alloc_beg, user_beg, user_end, alloc_end);

	// start poisoning
	// if assume alloc_beg is 8-byte aligned, we can use FastPoisonShadow()
	/* Fast */ PoisonShadow(alloc_beg, user_beg - alloc_beg, kAsanHeapLeftRedzoneMagic);
	PoisonShadow(user_beg, size, 0x0); // user_beg is already aligned to alignment
	uptr right_redzone_beg = RoundUpTo(user_end, alignment);
	/* Fast */ PoisonShadow(right_redzone_beg, alloc_end - right_redzone_beg, kAsanHeapRightRedzoneMagic);

	is_in_heap_operator_wrapper = false;

	return reinterpret_cast<void *>(user_beg);
}

void FREE(void *ptr)
{
	// PRINTF("\n[free] is_in_heap_operator_wrapper %d\n", is_in_heap_operator_wrapper);
	if (not asan_inited || is_in_heap_operator_wrapper)
	{
		BACKEND_FREE(ptr);
		return;
	}
	if (ptr == nullptr)
		return;

	is_in_heap_operator_wrapper = true;

	uptr user_beg = reinterpret_cast<uptr>(ptr);
	uptr alignment = SHADOW_GRANULARITY;
	CHECK(IsAligned(user_beg, alignment));
	// PRINTF("\n[Recycle] 0x%lx\n", user_beg);

	uptr chunk_beg = user_beg - sizeof(chunk);
	chunk *m = reinterpret_cast<chunk *>(chunk_beg);
	size_t user_size = m->user_size;
	// PRINTF("\n[Recycle] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", m->alloc_beg, user_beg, user_beg + user_size, m->alloc_beg + ComputeRZSize(user_size) * 2 + RoundUpTo(user_size, alignment));
	FastPoisonShadow(user_beg, RoundUpTo(user_size, alignment), kAsanHeapFreeMagic);
	size_t calcualted_alloc_size = ComputeRZSize(user_size) * 2 + RoundUpTo(user_size, alignment);

	size_t true_allocated_size = BACKEND_MALLOC_USABLE_SZIE((void *)m->alloc_beg);
	calcualted_alloc_size = true_allocated_size;

	QuarantineElement qe = {
		.alloc_beg = m->alloc_beg,
		.alloc_size = calcualted_alloc_size,
		.user_beg = user_beg,
		.user_size = user_size};
	QuarantineCache::put(qe);

	is_in_heap_operator_wrapper = false;
}

void *CALLOC(size_t n_elements, size_t elem_size)
{
	if (not asan_inited)
	{
		return BACKEND_CALLOC(n_elements, elem_size);
	}

	void *mem;
	size_t req = 0;
	if (n_elements != 0)
	{
		req = n_elements * elem_size;
		if (((n_elements | elem_size) & ~(size_t)0xffff) &&
			req / n_elements != elem_size)
		{
			req = MAX_SIZE_T; /* force downstream failure on overflow */
		}
	}
	mem = MALLOC(req);
	if (mem != nullptr)
	{
		memset(mem, 0, req);
	}
	return mem;
}

void *REALLOC(void *oldmem, size_t bytes)
{
	if (not asan_inited)
	{
		return BACKEND_REALLOC(oldmem, bytes);
	}

	void *mem = 0;
	if (oldmem == nullptr)
	{
		return MALLOC(bytes);
	}
	if (bytes == 0)
	{
		FREE(oldmem);
		return nullptr;
	}

	mem = MALLOC(bytes);

	if (mem != 0)
	{
		uptr chunk_beg = reinterpret_cast<uptr>(oldmem) - sizeof(chunk);
		chunk *m = reinterpret_cast<chunk *>(chunk_beg);
		size_t old_size = m->user_size;

		memcpy(mem, oldmem, bytes > old_size ? old_size : bytes);
		FREE(oldmem);
	}

	return mem;
}

size_t MALLOC_USABLE_SZIE(void *mem)
{
	uptr user_beg = reinterpret_cast<uptr>(mem);

	uptr chunk_beg = user_beg - sizeof(chunk);
	chunk *m = reinterpret_cast<chunk *>(chunk_beg);
	size_t user_size = m->user_size;

	return user_size;
}