#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
//#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <sched.h>
#include <stdarg.h>

#include "network.h"
#include "ring.h"
#include "framebuffer.h"
#include "llist.h"
#include "util.h"

#define CONNECTION_QUEUE_SIZE 16
#define THREAD_NAME_MAX 16
#define SCRATCH_STR_MAX 32
#define WHITESPACE_SEARCH_GARBAGE_THRESHOLD 32

#if DEBUG > 1
#define debug_printf(...) printf(__VA_ARGS__)
#define debug_fprintf(s, ...) fprintf(s, __VA_ARGS__)
#else
#define debug_printf(...)
#define debug_fprintf(...)
#endif

/* Theory Of Operation
 * ===================
 *
 * Using net_alloc the caller grabs a net struct. After that
 * he uses net_listen with the desired number of threads used
 * for accepting connections.
 *
 * Each of the threads used for accepting connections starts
 * another thread for each connection it accepted.
 *
 * The newly created thread then sets up a ring buffer to avoid
 * memmoves while parsing and starts reading data to it.
 * After receiving any number of bytes the thread tries to read
 * a valid command verb from the current read position in the
 * ring buffer. If that fails the thread tries to skip to the
 * next whitespace-separated token and tries to parse it as a
 * command verb. One a valid command verb is detected the
 * parser tries to fetch all arguments required to form a
 * complete command.
 * If there are any required parts missing from a command the
 * parser will assume that it has simply not been received yet
 * and go back to reading from the socket.
 */
static int one = 1;

void net_init(struct net* net, struct fb* fb, struct fb_size* fb_size, size_t pfring_size) {
	net->state = NET_STATE_IDLE;
	net->fb = fb;
	net->fb_size = fb_size;
	net->pfring_size = pfring_size;
}

static void net_listen_thread_cleanup_threadlist(struct net_thread *thread) {
	struct llist* threadlist = &thread->threadlist;
	struct net_connection_thread* conn_thread;

	llist_lock(threadlist);
	while(threadlist->head) {
		conn_thread = llist_entry_get_value(threadlist->head, struct net_connection_thread, list);
		pthread_cancel(conn_thread->thread);
		llist_unlock(threadlist)
		pthread_join(conn_thread->thread, NULL);
		llist_lock(threadlist);
	}
	llist_unlock(threadlist);
}

static void net_kill_threads(struct net* net) {
	net->state = NET_STATE_SHUTDOWN;
	pthread_cancel(net->listen_thread.thread);
	pthread_join(net->listen_thread.thread, NULL);
	net_listen_thread_cleanup_threadlist(&net->listen_thread);
}

void net_shutdown(struct net* net) {
	net_kill_threads(net);
	shutdown(net->socket, SHUT_RDWR);
	close(net->socket);
	net->state = NET_STATE_EXIT;
}

static inline int net_is_newline(char c) {
	return c == '\r' || c == '\n';
}

static inline int net_is_whitespace(char c) {
	switch(c) {
		case ' ':
		case '\n':
		case '\r':
		case '\t':
			return 1;
	}
	return 0;
}

static int net_skip_whitespace(struct ring* ring) {
	int cnt = 0;
	char c;
	while(pfring_any_available(ring)) {
		c = pfring_peek_one(ring);
		if(!net_is_whitespace(c)) {
			goto done;
		}
		pfring_inc_read(ring);
		cnt++;
	}
done:
	return cnt ? cnt : -1;
}

static off_t net_next_whitespace(struct ring* ring) {
	off_t offset = 0;
	char c, *read_before = ring->ptr_read;
	int err;
	while(pfring_any_available(ring)) {
		c = pfring_read_one(ring);
		if(net_is_whitespace(c)) {
			goto done;
		}
		if(offset++ >= WHITESPACE_SEARCH_GARBAGE_THRESHOLD) {
			err = -EINVAL;
			goto fail;
		}
	}
	err = -1; // No next whitespace found
	goto fail;

done:
	ring->ptr_read = read_before;
	return offset;
fail:
	ring->ptr_read = read_before;
	return err;
}

static uint32_t net_str_to_uint32_10(struct ring* ring, ssize_t len) {
	uint32_t val = 0;
	int radix;
	char c;
	for(radix = 0; radix < len; radix++) {
		c = pfring_read_one(ring);
		val = val * 10 + (c - '0');
	}
	return val;
}

// Separate implementation to keep performance high
static uint32_t net_str_to_uint32_16(struct ring* ring, ssize_t len) {
	uint32_t val = 0;
	char c;
	int radix, lower;
	for(radix = 0; radix < len; radix++) {
		// Could be replaced by a left shift
		val *= 16;
		c = pfring_read_one(ring);
		lower = c | 0x20;
		if(lower >= 'a') {
			val += lower - 'a' + 10;
		} else {
			val += lower - '0';
		}
	}
	return val;
}

static ssize_t net_sock_printf(int socket, char* scratch_str, size_t scratch_len, char* fmt, ...) {
	ssize_t ret;
	size_t len;
	off_t write_cnt = 0;

	va_list vargs;
	va_start(vargs, fmt);
	ret = vsnprintf(scratch_str, scratch_len, fmt, vargs);
	va_end(vargs);

	if(ret >= scratch_len) {
		ret = -ENOBUFS;
	}

	if(ret < 0) {
		goto out;
	}

	len = ret;

	while(write_cnt < len) {
		ssize_t write_len;
		if((write_len = write(socket, scratch_str + write_cnt, len - write_cnt)) < 0) {
			ret = -errno;
			goto out;
		}
		write_cnt += write_len;
	}
out:
	return ret;
}

static void net_connection_thread_cleanup_socket(struct net_connection_thread *thread) {
	shutdown(thread->threadargs.socket, SHUT_RDWR);
	close(thread->threadargs.socket);
}

static void net_connection_thread_cleanup_self(struct net_connection_thread *thread) {
	pthread_mutex_lock(&thread->threadargs.net_thread->list_lock);
	llist_remove(&thread->list);
	pthread_mutex_unlock(&thread->threadargs.net_thread->list_lock);
	free(thread);
}

static void* net_connection_thread(void* args) {
	struct net_connection_threadargs* threadargs = args;
	int err, socket = threadargs->socket;
	struct net* net = threadargs->net;
	struct net_connection_thread* thread =
		container_of(threadargs, struct net_connection_thread, threadargs);

	struct fb* fb;
	struct fb_size* fbsize;
	union fb_pixel pixel;
	unsigned int x, y;

	off_t offset;
	ssize_t read_len;
	char* last_cmd;

	/*
		A small ring buffer (64kB * 64k connections = ~4GB at max) to prevent memmoves.
		Using a ring buffer prevents us from having to memmove but we do have to handle
		Wrap arounds. This means that we can not use functions like strncmp safely without
		checking for wraparounds
	*/
	struct ring* ring = &thread->ring;

	char scratch_str[SCRATCH_STR_MAX];

/*
#ifndef FEATURE_BROKEN_PTHREAD
	cpu_set_t nodemask;
	int cpuid = sched_getcpu();
	if(cpuid < 0) {
		fprintf(stderr, "Failed to get cpuid of network thread, continuing without affinity setting\n");
	} else {
		CPU_ZERO(&nodemask);
		CPU_SET(cpuid, &nodemask);
		if((err = pthread_setaffinity_np(pthread_self(), sizeof(nodemask), &nodemask))) {
			fprintf(stderr, "Failed to set cpu affinity, continuing without affinity setting: %s (%d)\n", strerror(err), err);
		}
	}
#endif
*/

	fb = net->fb;
	fbsize = fb_get_size(fb);

	pfring_init(ring, thread->pfring_data, net->pfring_size);
recv:
	while(net->state != NET_STATE_SHUTDOWN) {
		read_len = read(socket, ring->ptr_write, pfring_free_space_contig(ring));
		if(read_len <= 0) {
			if(read_len < 0) {
				err = -errno;
				fprintf(stderr, "Client socket failed %d => %s\n", errno, strerror(errno));
			}
			goto fail_ring;
		}
#ifdef FEATURE_STATISTICS
		thread->byte_count += read_len;
#endif
		debug_printf("Read %zd bytes\n", read_len);
		pfring_advance_write(ring, read_len);

		while(pfring_any_available(ring)) {
			last_cmd = ring->ptr_read;

			if(!pfring_memcmp(ring, "PX", strlen("PX"), NULL)) {
				if((err = net_skip_whitespace(ring)) < 0) {
					debug_fprintf(stderr, "No whitespace after PX cmd\n");
					goto recv_more;
				}
				if((offset = net_next_whitespace(ring)) < 0) {
					debug_fprintf(stderr, "No more whitespace found, missing X\n");
					goto recv_more;
				}
				x = net_str_to_uint32_10(ring, offset);
				if((err = net_skip_whitespace(ring)) < 0) {
					debug_fprintf(stderr, "No whitespace after X coordinate\n");
					goto recv_more;
				}
				if((offset = net_next_whitespace(ring)) < 0) {
					debug_fprintf(stderr, "No more whitespace found, missing Y\n");
					goto recv_more;
				}
				y = net_str_to_uint32_10(ring, offset);
				if((err = net_skip_whitespace(ring)) < 0) {
					debug_fprintf(stderr, "No whitespace after Y coordinate\n");
					goto recv_more;
				}
				x += thread->offset.x;
				y += thread->offset.y;
				if(unlikely(net_is_newline(pfring_peek_prev(ring)))) {
					// Get pixel
					if(x < fbsize->width && y < fbsize->height) {
						if((err = net_sock_printf(socket, scratch_str, sizeof(scratch_str), "PX %u %u %06x\n",
							x, y, fb_get_pixel(net->fb, x, y).abgr >> 8)) < 0) {
							fprintf(stderr, "Failed to write out pixel value: %d => %s\n", err, strerror(-err));
							goto fail_ring;
						}
					}
				} else {
					// Set pixel
					if((offset = net_next_whitespace(ring)) < 0) {
						debug_fprintf(stderr, "No more whitespace found, missing color\n");
						goto recv_more;
					}
					if(offset > 6) {
						pixel.abgr = net_str_to_uint32_16(ring, offset);
					} else {
						pixel.abgr = net_str_to_uint32_16(ring, offset) << 8;
						pixel.color.alpha = 0xFF;
					}

					debug_printf("Got pixel command: PX %u %u %02x%02x%02x%02x\n", x, y,
					             pixel.color.color_bgr.red, pixel.color.color_bgr.green,
					             pixel.color.color_bgr.blue, pixel.color.alpha);
					if(x < fbsize->width && y < fbsize->height) {
#ifdef FEATURE_STATISTICS
#ifdef FEATURE_PIXEL_COUNT
						fb->pixel_count++;
#endif
#endif
#ifdef FEATURE_ALPHA_BLENDING
						if (pixel.color.alpha != 0xFF) {
							union fb_pixel old_pixel = fb_get_pixel(fb, x, y);
							FB_ALPHA_BLEND_PIXEL(pixel, pixel, old_pixel);
						}
#endif
						fb_set_pixel(fb, x, y, &pixel);
					} else {
						debug_printf("Got pixel outside screen area: %u, %u outside %u, %u\n", x, y, fbsize->width, fbsize->height);
					}
				}
			}
#ifdef FEATURE_SIZE
			else if(!pfring_memcmp(ring, "SIZE", strlen("SIZE"), NULL)) {
				if((err = net_sock_printf(socket, scratch_str, sizeof(scratch_str), "SIZE %u %u\n", fbsize->width, fbsize->height)) < 0) {
					fprintf(stderr, "Failed to write out size: %d => %s\n", err, strerror(-err));
					goto fail_ring;
				}
			}
#endif
#ifdef FEATURE_OFFSET
			else if(!pfring_memcmp(ring, "OFFSET", strlen("OFFSET"), NULL)) {
				if((err = net_skip_whitespace(ring)) < 0) {
					goto recv_more;
				}
				if((offset = net_next_whitespace(ring)) < 0) {
					goto recv_more;
				}
				x = net_str_to_uint32_10(ring, offset);
				if((err = net_skip_whitespace(ring)) < 0) {
					goto recv_more;
				}
				if((offset = net_next_whitespace(ring)) < 0) {
					goto recv_more;
				}
				y = net_str_to_uint32_10(ring, offset);
				thread->offset.x = x;
				thread->offset.y = y;
			}
#endif
			else {
				if((offset = net_next_whitespace(ring)) >= 0) {
					debug_printf("Encountered unknown command\n");
					pfring_advance_read(ring, offset);
				} else {
					if(offset == -EINVAL) {
						// We have a missbehaving client
						goto fail_ring;
					}
					goto recv;
				}
			}

			net_skip_whitespace(ring);
		}
	}

fail_ring:
//fail_socket:
	net_connection_thread_cleanup_socket(thread);
	net_connection_thread_cleanup_self(thread);
//fail:
	pthread_detach(pthread_self());
	return NULL;

recv_more:
	ring->ptr_read = last_cmd;
	goto recv;
}

static void* net_listen_thread(void* args) {
	int err, socket;
	struct net* net = args;
	struct net_thread* thread = &net->listen_thread;

	struct llist* threadlist = &thread->threadlist;
	struct net_connection_thread* conn_thread;
	pthread_mutex_init(&thread->list_lock, NULL);

	llist_init(threadlist);
	thread->initialized = true;

	while(net->state != NET_STATE_SHUTDOWN) {
		socket = accept(net->socket, NULL, NULL);
		if(socket < 0) {
			err = -errno;
			fprintf(stderr, "Got error %d => %s, shutting down\n", errno, strerror(errno));
			goto fail_threadlist;
		}
		printf("Got a new connection\n");

		conn_thread = calloc(1, sizeof(struct net_connection_thread) + net->pfring_size);
		if(!conn_thread) {
			fprintf(stderr, "Failed to allocate memory for connection thread\n");
			goto fail_connection;
		}
		llist_entry_init(&conn_thread->list);
		conn_thread->threadargs.socket = socket;
		conn_thread->threadargs.net = net;
		conn_thread->threadargs.net_thread = thread;

		pthread_mutex_lock(&thread->list_lock);
		if((err = -pthread_create(&conn_thread->thread, NULL, net_connection_thread, &conn_thread->threadargs))) {
			fprintf(stderr, "Failed to create thread: %d => %s\n", err, strerror(-err));
			pthread_mutex_unlock(&thread->list_lock);
			goto fail_thread_entry;
		}

		llist_append(threadlist, &conn_thread->list);
		pthread_mutex_unlock(&thread->list_lock);

		continue;

fail_thread_entry:
		free(conn_thread);
fail_connection:
		shutdown(socket, SHUT_RDWR);
		close(socket);
	}
fail_threadlist:
	net_listen_thread_cleanup_threadlist(thread);
//fail:
	return NULL;

}

int net_listen(struct net* net, struct sockaddr_storage* addr, size_t addr_len) {
	int err = 0;
	char host_tmp[32];
	const char *host_str;
	unsigned short port;

	assert(net->state == NET_STATE_IDLE);
	net->state = NET_STATE_LISTEN;

	// Create socket
	net->socket = socket(addr->ss_family, SOCK_STREAM, 0);
	if(net->socket < 0) {
		fprintf(stderr, "Failed to create socket\n");
		err = -errno;
		goto fail;
	}
	setsockopt(net->socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

	host_str = inet_ntop(addr->ss_family, addr, host_tmp, sizeof(host_tmp));
	assert(host_str);

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

		port = ntohs(addr6->sin6_port);
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;

		port = ntohs(addr4->sin_port);
	}

	// Start listening
	if(bind(net->socket, (struct sockaddr*)addr, addr_len) < 0) {
		fprintf(stderr, "Failed to bind to %s:%u\n", host_tmp, port);
		err = -errno;
		goto fail_socket;
	}

	if(listen(net->socket, CONNECTION_QUEUE_SIZE)) {
		fprintf(stderr, "Failed to start listening: %d => %s\n", errno, strerror(errno));
		err = -errno;
		goto fail_socket;
	}

	if (addr->ss_family == AF_INET6) {
		printf("Listening on [%s]:%u\n", host_tmp, port);
	} else {
		printf("Listening on %s:%u\n", host_tmp, port);
	}

	// Setup listen thread
	do {
		err = -pthread_create(&net->listen_thread.thread, NULL, net_listen_thread, net);
		if(err) {
			fprintf(stderr, "Failed to create listen pthread\n");
			goto fail_pthread_create;
		}
	} while (0);

	return 0;

fail_pthread_create:
	net_kill_threads(net);
fail_socket:
	close(net->socket);
	shutdown(net->socket, SHUT_RDWR);
fail:
	net->state = NET_STATE_IDLE;
	return err;
}
