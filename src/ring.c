#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "ring.h"

void pfring_init(struct ring* ring, char *buff, size_t size) {
	int err;

	ring->data = buff;
	ring->ptr_read = ring->data;
	ring->ptr_write = ring->data;
	ring->size = size;
}

// Take a peek into the ring buffer
int pfring_peek(struct ring* ring, char* data, size_t len) {
	size_t avail_contig;

	if(pfring_available(ring) < len) {
		return -EINVAL;
	}

	avail_contig = pfring_available_contig(ring);

	if(avail_contig >= len) {
		memcpy(data, ring->ptr_read, len);
	} else {
		memcpy(data, ring->ptr_read, avail_contig);
		memcpy(data + avail_contig, ring->data, len - avail_contig);
	}

	return 0;
}

// Read from this ring buffer
int pfring_read(struct ring* ring, char* data, size_t len) {
	size_t avail_contig;

	if(pfring_available(ring) < len) {
		return -EINVAL;
	}

	avail_contig = pfring_available_contig(ring);

	if(avail_contig >= len) {
		memcpy(data, ring->ptr_read, len);
		ring->ptr_read = pfring_next(ring, ring->ptr_read + len - 1);
	} else {
		memcpy(data, ring->ptr_read, avail_contig);
		memcpy(data + avail_contig, ring->data, len - avail_contig);
		ring->ptr_read = ring->data + len - avail_contig;
	}

	return 0;
}

// Write to this ring buffer
int pfring_write(struct ring* ring, char* data, size_t len) {
	size_t free_contig;

	if(pfring_free_space(ring) < len) {
		return -EINVAL;
	}

	free_contig = pfring_free_space_contig(ring);

	if(free_contig >= len) {
		memcpy(ring->ptr_write, data, len);
		ring->ptr_write = pfring_next(ring, ring->ptr_write + len - 1);
	} else {
		memcpy(ring->ptr_write, data, free_contig);
		memcpy(ring->data, data + free_contig, len - free_contig);
		ring->ptr_write = ring->data + len - free_contig;
	}
	return 0;
}
