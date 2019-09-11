#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <assert.h>

#include "libusbi.h"
#include "hotplug.h"

static int usbi_hotplug_match_cb(struct libusb_context *ctx,
	struct libusb_device *dev, libusb_hotplug_event event,
	struct libusb_hotplug_callback *hotplug_cb)
{
	if (!(hotplug_cb->flags & event)) {
		return 0;
	}

	if ((hotplug_cb->flags & USBI_HOTPLUG_VENDOR_ID_VALID) &&
	    hotplug_cb->vendor_id != dev->device_descriptor.idVendor) {
		return 0;
	}

	if ((hotplug_cb->flags & USBI_HOTPLUG_PRODUCT_ID_VALID) &&
	    hotplug_cb->product_id != dev->device_descriptor.idProduct) {
		return 0;
	}

	if ((hotplug_cb->flags & USBI_HOTPLUG_DEV_CLASS_VALID) &&
	    hotplug_cb->dev_class != dev->device_descriptor.bDeviceClass) {
		return 0;
	}

	return hotplug_cb->cb(ctx, dev, event, hotplug_cb->user_data);
}

void usbi_hotplug_match(struct libusb_context *ctx, struct libusb_device *dev,
	libusb_hotplug_event event)
{
	struct libusb_hotplug_callback *hotplug_cb, *next;
	int ret;

	pthread_mutex_lock(&ctx->hotplug_cbs_lock);

	list_for_each_entry_safe(hotplug_cb, next, &ctx->hotplug_cbs, list, struct libusb_hotplug_callback) {
		if (hotplug_cb->flags & USBI_HOTPLUG_NEEDS_FREE) {
			/* process deregistration in usbi_hotplug_deregister() */
			continue;
		}

		pthread_mutex_unlock(&ctx->hotplug_cbs_lock);
		ret = usbi_hotplug_match_cb(ctx, dev, event, hotplug_cb);
		pthread_mutex_lock(&ctx->hotplug_cbs_lock);

		if (ret) {
			list_del(&hotplug_cb->list);
			free(hotplug_cb);
		}
	}

	pthread_mutex_unlock(&ctx->hotplug_cbs_lock);
}

void usbi_hotplug_notification(struct libusb_context *ctx, struct libusb_device *dev,
	libusb_hotplug_event event)
{
	int pending_events;
	struct libusb_hotplug_message *message = calloc(1, sizeof(*message));

	if (!message) {
		usbi_err(ctx, "error allocating hotplug message");
		return;
	}

	message->event = event;
	message->device = dev;

	pthread_mutex_lock(&ctx->event_data_lock);
	pending_events = usbi_pending_events(ctx);
	list_add_tail(&message->list, &ctx->hotplug_msgs);
	if (!pending_events)
		usbi_signal_event(ctx);
	pthread_mutex_unlock(&ctx->event_data_lock);
}

int API_EXPORTED libusb_hotplug_register_callback(libusb_context *ctx,
	libusb_hotplug_event events, libusb_hotplug_flag flags,
	int vendor_id, int product_id, int dev_class,
	libusb_hotplug_callback_fn cb_fn, void *user_data,
	libusb_hotplug_callback_handle *callback_handle)
{
	struct libusb_hotplug_callback *new_callback;

	/* check for sane values */
	if ((!events || (~(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) & events)) ||
	    (flags && (~LIBUSB_HOTPLUG_ENUMERATE & flags)) ||
	    (LIBUSB_HOTPLUG_MATCH_ANY != vendor_id && (~0xffff & vendor_id)) ||
	    (LIBUSB_HOTPLUG_MATCH_ANY != product_id && (~0xffff & product_id)) ||
	    (LIBUSB_HOTPLUG_MATCH_ANY != dev_class && (~0xff & dev_class)) ||
	    !cb_fn) {
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	/* check for hotplug support */
	if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
		return LIBUSB_ERROR_NOT_SUPPORTED;
	}

	USBI_GET_CONTEXT(ctx);

	new_callback = calloc(1, sizeof(*new_callback));
	if (!new_callback) {
		return LIBUSB_ERROR_NO_MEM;
	}

	new_callback->flags = (uint8_t)events;
	if (LIBUSB_HOTPLUG_MATCH_ANY != vendor_id) {
		new_callback->flags |= USBI_HOTPLUG_VENDOR_ID_VALID;
		new_callback->vendor_id = (uint16_t)vendor_id;
	}
	if (LIBUSB_HOTPLUG_MATCH_ANY != product_id) {
		new_callback->flags |= USBI_HOTPLUG_PRODUCT_ID_VALID;
		new_callback->product_id = (uint16_t)product_id;
	}
	if (LIBUSB_HOTPLUG_MATCH_ANY != dev_class) {
		new_callback->flags |= USBI_HOTPLUG_DEV_CLASS_VALID;
		new_callback->dev_class = (uint8_t)dev_class;
	}
	new_callback->cb = cb_fn;
	new_callback->user_data = user_data;

	pthread_mutex_lock(&ctx->hotplug_cbs_lock);

	/* protect the handle by the context hotplug lock */
	new_callback->handle = ctx->next_hotplug_cb_handle++;

	/* handle the unlikely case of overflow */
	if (ctx->next_hotplug_cb_handle < 0)
		ctx->next_hotplug_cb_handle = 1;

	list_add(&new_callback->list, &ctx->hotplug_cbs);

	pthread_mutex_unlock(&ctx->hotplug_cbs_lock);

	usbi_dbg("new hotplug cb %p with handle %d", new_callback, new_callback->handle);

	if ((flags & LIBUSB_HOTPLUG_ENUMERATE) && (events & LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED)) {
		ssize_t i, len;
		struct libusb_device **devs;

		len = libusb_get_device_list(ctx, &devs);
		if (len < 0) {
			libusb_hotplug_deregister_callback(ctx,
							new_callback->handle);
			return (int)len;
		}

		for (i = 0; i < len; i++) {
			usbi_hotplug_match_cb(ctx, devs[i],
					LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED,
					new_callback);
		}

		libusb_free_device_list(devs, 1);
	}


	if (callback_handle)
		*callback_handle = new_callback->handle;

	return LIBUSB_SUCCESS;
}

void API_EXPORTED libusb_hotplug_deregister_callback(struct libusb_context *ctx,
	libusb_hotplug_callback_handle callback_handle)
{
	struct libusb_hotplug_callback *hotplug_cb;
	int deregistered = 0;

	/* check for hotplug support */
	if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
		return;
	}

	USBI_GET_CONTEXT(ctx);

	usbi_dbg("deregister hotplug cb %d", callback_handle);

	pthread_mutex_lock(&ctx->hotplug_cbs_lock);
	list_for_each_entry(hotplug_cb, &ctx->hotplug_cbs, list, struct libusb_hotplug_callback) {
		if (callback_handle == hotplug_cb->handle) {
			/* Mark this callback for deregistration */
			hotplug_cb->flags |= USBI_HOTPLUG_NEEDS_FREE;
			deregistered = 1;
		}
	}
	pthread_mutex_unlock(&ctx->hotplug_cbs_lock);

	if (deregistered) {
		int pending_events;

		pthread_mutex_lock(&ctx->event_data_lock);
		pending_events = usbi_pending_events(ctx);
		ctx->event_flags |= USBI_EVENT_HOTPLUG_CB_DEREGISTERED;
		if (!pending_events)
			usbi_signal_event(ctx);
		pthread_mutex_unlock(&ctx->event_data_lock);
	}
}

void usbi_hotplug_deregister(struct libusb_context *ctx, int forced)
{
	struct libusb_hotplug_callback *hotplug_cb, *next;

	pthread_mutex_lock(&ctx->hotplug_cbs_lock);
	list_for_each_entry_safe(hotplug_cb, next, &ctx->hotplug_cbs, list, struct libusb_hotplug_callback) {
		if (forced || (hotplug_cb->flags & USBI_HOTPLUG_NEEDS_FREE)) {
			usbi_dbg("freeing hotplug cb %p with handle %d", hotplug_cb,
				 hotplug_cb->handle);
			list_del(&hotplug_cb->list);
			free(hotplug_cb);
		}
	}
	pthread_mutex_unlock(&ctx->hotplug_cbs_lock);
}
