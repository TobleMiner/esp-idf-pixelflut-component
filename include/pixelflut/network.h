#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

struct net;

#include "framebuffer.h"
#include "llist.h"
#include "ring.h"

enum {
	NET_STATE_IDLE,
	NET_STATE_LISTEN,
	NET_STATE_SHUTDOWN,
	NET_STATE_EXIT
};

struct net_thread {
	TaskHandle_t thread;
	bool initialized;
	pthread_mutex_t list_lock;
	unsigned int num_connections;

	struct llist threadlist;
	bool do_exit;
	bool has_terminated;
};

struct net {
	size_t pfring_size;

	unsigned int state;

	int socket;

	struct fb* fb;

	unsigned int num_threads;
	struct net_thread listen_thread;
	struct fb_size* fb_size;
	TaskHandle_t exit_notification_task;
};

struct net_connection_threadargs {
	struct net* net;
	struct net_thread* net_thread;
	int socket;
};

struct net_connection_thread {
	TaskHandle_t thread;
	struct llist_entry list;
	struct net_connection_threadargs threadargs;
	struct {
		unsigned int x;
		unsigned int y;
	} offset;
	uint32_t byte_count;
	bool do_exit;
	bool has_terminated;

	struct ring ring;

	char pfring_data[0];
};

#ifndef likely
#define likely(x)	__builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect((x),0)
#endif

void net_init(struct net* network, struct fb* fb, struct fb_size* fb_size, size_t pfring_size);

void net_shutdown(struct net* net);
int net_listen(struct net* net, struct sockaddr_storage* addr, size_t addr_len);

#endif
