#ifndef _RING_H_
#define _RING_H_

#include <stdbool.h>

struct ring {
	size_t size;
	char* data;
	char* ptr_read, *ptr_write;
};

void pfring_init(struct ring* ring, char *buff, size_t size);

int pfring_peek(struct ring* ring, char* data, size_t len);
int pfring_read(struct ring* ring, char* data, size_t len);
int pfring_write(struct ring* ring, char* data, size_t len);

// Optimized inline funnctions
static inline bool pfring_any_available(struct ring* ring) {
	return ring->ptr_read != ring->ptr_write;
}

// Take a small peek into the buffer
static inline char pfring_peek_one(struct ring* ring) {
	return *ring->ptr_read;
}

// Peek previous byte
static inline char pfring_peek_prev(struct ring* ring) {
	if(ring->ptr_read - 1 < ring->data) {
		return *(ring->data + ring->size - 1);
	}
	return *(ring->ptr_read - 1);
}

// Pointer to next byte to read from ringbuffer
static inline char* pfring_next(struct ring* ring, char* ptr) {
	if(ptr < ring->data + ring->size - 1) {
		return ptr + 1;
	}
	return ring->data;
}

// Read one byte from the buffer
static inline char pfring_read_one(struct ring* ring) {
	char c = *ring->ptr_read;
	ring->ptr_read = pfring_next(ring, ring->ptr_read);
	return c;
}

static inline void pfring_inc_read(struct ring* ring) {
	ring->ptr_read = pfring_next(ring, ring->ptr_read);
}

// Number of contiguous free bytes after ring->write_ptr
static inline size_t pfring_free_space_contig(struct ring* ring) {
	if(ring->ptr_read > ring->ptr_write) {
		return ring->ptr_read - ring->ptr_write - 1;
	}
	return ring->size - (ring->ptr_write - ring->data) - (ring->ptr_read == ring->data ? 1 : 0);
}

static inline void pfring_advance_read(struct ring* ring, off_t offset) {
	assert(offset >= 0);
	assert(offset <= ring->size);

	if(offset) {
		if(ring->ptr_read + offset < ring->data + ring->size) {
			ring->ptr_read = pfring_next(ring, ring->ptr_read + offset - 1);
		} else {
			ring->ptr_read = offset - ring->size + ring->ptr_read;
		}
	}
}

static inline void pfring_advance_write(struct ring* ring, off_t offset) {
	assert(offset >= 0);
	assert(offset <= ring->size);

	if(offset) {
		if(ring->ptr_write + offset < ring->data + ring->size) {
			ring->ptr_write = pfring_next(ring, ring->ptr_write + offset - 1);
		} else {
			ring->ptr_write = offset - ring->size + ring->ptr_write;
		}
	}
}

// Number of bytes that can be read from ringbuffer
static inline size_t pfring_available(struct ring* ring) {
	if(ring->ptr_write >= ring->ptr_read) {
		return ring->ptr_write - ring->ptr_read;
	}
	return ring->size - (ring->ptr_read - ring->ptr_write);
}

// Number of virtually contiguous bytes that can be read from ringbuffer
static inline size_t pfring_available_contig(struct ring* ring) {
	if(ring->ptr_write >= ring->ptr_read) {
		return ring->ptr_write - ring->ptr_read;
	}
	return ring->size - (ring->ptr_read - ring->data);
}

// Number of free bytes
static inline size_t pfring_free_space(struct ring* ring) {
	if(ring->ptr_read > ring->ptr_write) {
		return ring->ptr_read - ring->ptr_write - 1;
	}
	return ring->size - (ring->ptr_write - ring->ptr_read) - 1;
}


/*
 Behaves totally different from memcmp!
 Return:
	< 0 error (not enough data in buffer)
	= 0 match
	> 0 no match
*/
static inline int pfring_memcmp(struct ring* ring, char* ref, unsigned int len, char** next_pos) {
	size_t avail_contig;

	if(pfring_available(ring) < len) {
		return -EINVAL;
	}

	avail_contig = pfring_available_contig(ring);

	if(avail_contig >= len) {
		// We are lucky
		if(memcmp(ring->ptr_read, ref, len)) {
			return 1;
		}
		if(next_pos) {
			*next_pos = pfring_next(ring, ring->ptr_read + len - 1);
		} else {
			pfring_advance_read(ring, len);
		}
		return 0;
	}


	// We (may) need to perform two memcmps
	if(memcmp(ring->ptr_read, ref, avail_contig) || memcmp(ring->data, ref + avail_contig, len - avail_contig)) {
		return 1;
	}
	if(next_pos) {
		*next_pos = ring->data + len - avail_contig;
	} else {
		pfring_advance_read(ring, len);
	}
	return 0;
}

#endif
