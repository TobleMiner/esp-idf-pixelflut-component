#pragma once

#include "pixelflut/framebuffer.h"
#include "pixelflut/network.h"

typedef struct {
	struct fb *fb;
	struct net net;
} pixelflut_t;

int pixelflut_init(pixelflut_t *pixelflut, unsigned int canvas_width, unsigned int canvas_height, unsigned int buffer_size);
void pixelflut_free(pixelflut_t *pixelflut);
int pixelflut_listen(pixelflut_t *pixelflut);
unsigned int pixelflut_get_num_connections(pixelflut_t *pixelflut);
