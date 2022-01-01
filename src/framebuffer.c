#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "framebuffer.h"

int fb_alloc(struct fb** framebuffer, unsigned int width, unsigned int height) {
	int err = 0;
	size_t fb_size;

	struct fb* fb = malloc(sizeof(struct fb));
	if(!fb) {
		err = -ENOMEM;
		goto fail;
	}

	fb->size.width = width;
	fb->size.height = height;
	fb_size = width * height;

	fb->pixels = calloc(width * height, sizeof(union fb_pixel));
	if(!fb->pixels) {
		err = -ENOMEM;
		goto fail_fb;
	}

	while (fb_size--) {
		if (is_big_endian()) {
			fb->pixels[fb_size].color_be.alpha = 0xff;
		} else {
			fb->pixels[fb_size].color.alpha = 0xff;
		}
	}

	*framebuffer = fb;
	return 0;

fail_fb:
	free(fb);
fail:
	return err;
}

void fb_free(struct fb* fb) {
	free(fb->pixels);
	free(fb);
}

void fb_set_pixel_rgb(struct fb* fb, unsigned int x, unsigned int y, uint8_t red, uint8_t green, uint8_t blue) {
	union fb_pixel* target;
	assert(x < fb->size.width);
	assert(y < fb->size.height);

	target = &(fb->pixels[y * fb->size.width + x]);
	target->color.color_bgr.red = red;
	target->color.color_bgr.green = green;
	target->color.color_bgr.blue = blue;
}

void fb_clear_rect(struct fb* fb, unsigned int x, unsigned int y, unsigned int width, unsigned int height) {
	while(height--) {
		if(y + height >= fb->size.height) {
			continue;
		}
		union fb_pixel* pix = fb_get_line_base(fb, y + height);
		pix += x;
		memset(pix, 0, sizeof(union fb_pixel) * max(0, min(width, (int)fb->size.width - (int)x)));
	}
}

static void fb_set_size(struct fb* fb, unsigned int width, unsigned int height) {
	fb->size.width = width;
	fb->size.height = height;
}

int fb_resize(struct fb* fb, unsigned int width, unsigned int height) {
	int err = 0;
	union fb_pixel* fbmem, *oldmem;
	struct fb_size oldsize = *fb_get_size(fb);
	size_t memsize = width * height * sizeof(union fb_pixel);
	size_t oldmemsize = oldsize.width * oldsize.height * sizeof(union fb_pixel);
	fbmem = malloc(memsize);
	if(!fbmem) {
		err = -ENOMEM;
		goto fail;
	}
	memset(fbmem, 0, memsize);

	oldmem = fb->pixels;
	// Try to prevent oob writes
	if(oldmemsize > memsize) {
		fb_set_size(fb, width, height);
		fb->pixels = fbmem;
	} else {
		fb->pixels = fbmem;
		fb_set_size(fb, width, height);
	}
	free(oldmem);
fail:
	return err;
}

void fb_copy(struct fb* dst, struct fb* src) {
	assert(dst->size.width == src->size.width);
	assert(dst->size.height == src->size.height);
	memcpy(dst->pixels, src->pixels, dst->size.width * dst->size.height * sizeof(union fb_pixel));
}
