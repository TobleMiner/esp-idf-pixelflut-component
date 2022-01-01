#include <errno.h>
#include <stdlib.h>

#include "pixelflut.h"

int pixelflut_init(pixelflut_t *pixelflut, unsigned int canvas_width, unsigned int canvas_height, unsigned int buffer_size) {
	struct fb *fb;
	int err;

	err = fb_alloc(&fb, canvas_width, canvas_height);
	if (err) {
		return err;
	}
	pixelflut->fb = fb;

	net_init(&pixelflut->net, fb, &fb->size, buffer_size);

	return 0;
}

void pixelflut_free(pixelflut_t *pixelflut) {
	net_shutdown(&pixelflut->net);
	fb_free(pixelflut->fb);
}

int pixelflut_listen(pixelflut_t *pixelflut) {
	struct sockaddr_in listen_address = {
		.sin_family = AF_INET,
		.sin_port = htons(1234),
		.sin_addr.s_addr = htonl(0)
	};

	return net_listen(&pixelflut->net,
			  (struct sockaddr_storage *)&listen_address,
			  sizeof(listen_address));
}
