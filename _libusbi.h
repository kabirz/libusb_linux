
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>
#include <poll.h>
#include <pthread.h>
#include <sys/syscall.h>

#include "libusb.h"
#include "version.h"

struct list_head {
	struct list_head *prev, *next;
};

static inline void list_init(struct list_head *entry)
{
	entry->prev = entry->next = entry;
}

static inline void list_add(struct list_head *entry, struct list_head *head)
{
	entry->next = head->next;
	entry->prev = head;
	head->next->prev = entry;
	head->next = entry;
}

static inline void list_add_tail(struct list_head *entry,
				 struct list_head *head)
{
	entry->next = head;
	entry->prev = head->prev;
	head->prev->next = entry;
	head->prev = entry;
}

static inline void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = entry->prev = NULL;
}

static inline void list_cut(struct list_head *list, struct list_head *head)
{
	if (((head)->next == (head)))
		return;
	list->next = head->next;
	list->next->prev = list;
	list->prev = head->prev;
	list->prev->next = list;
	list_init(head);
}

static inline void *usbi_reallocf(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);

	if (!ret)
		free(ptr);
	return ret;
}

void usbi_log(struct libusb_context *ctx, enum libusb_log_level level,
	      const char *function, const char *format, ...) __attribute__((__format__(__printf__, 4, 5)));
void usbi_log_v(struct libusb_context *ctx, enum libusb_log_level level,
		const char *function, const char *format, va_list args) __attribute__((__format__(__printf__, 4, 0)));
extern struct libusb_context *usbi_default_context;
struct pollfd;
struct libusb_context {
	enum libusb_log_level debug;
	int debug_fixed;
	libusb_log_cb log_handler;
	int event_pipe[2];
	struct list_head usb_devs;
	pthread_mutex_t usb_devs_lock;
	struct list_head open_devs;
	pthread_mutex_t open_devs_lock;
	struct list_head hotplug_cbs;
	libusb_hotplug_callback_handle next_hotplug_cb_handle;
	pthread_mutex_t hotplug_cbs_lock;
	struct list_head flying_transfers;
	pthread_mutex_t flying_transfers_lock;
	libusb_pollfd_added_cb fd_added_cb;
	libusb_pollfd_removed_cb fd_removed_cb;
	void *fd_cb_user_data;
	pthread_mutex_t events_lock;
	int event_handler_active;
	pthread_key_t event_handling_key;
	pthread_mutex_t event_waiters_lock;
	pthread_cond_t event_waiters_cond;
	pthread_mutex_t event_data_lock;
	unsigned int event_flags;
	unsigned int device_close;
	struct list_head ipollfds;
	struct list_head removed_ipollfds;
	struct pollfd *pollfds;
	nfds_t pollfds_cnt;
	struct list_head hotplug_msgs;
	struct list_head completed_transfers;
	struct list_head list;
	__attribute__((aligned(sizeof(void *)))) unsigned char os_priv[ZERO_SIZED_ARRAY];
};

enum usbi_event_flags {
	USBI_EVENT_POLLFDS_MODIFIED = 1U << 0,
	USBI_EVENT_USER_INTERRUPT = 1U << 1,
	USBI_EVENT_HOTPLUG_CB_DEREGISTERED = 1U << 2,
};

struct libusb_device {
	pthread_mutex_t lock;
	int refcnt;
	struct libusb_context *ctx;
	uint8_t bus_number;
	uint8_t port_number;
	struct libusb_device *parent_dev;
	uint8_t device_address;
	uint8_t num_configurations;
	enum libusb_speed speed;
	struct list_head list;
	unsigned long session_data;
	struct libusb_device_descriptor device_descriptor;
	int attached;
	__attribute__((aligned(sizeof(void *)))) unsigned char os_priv[ZERO_SIZED_ARRAY];
};

struct libusb_device_handle {
	pthread_mutex_t lock;
	unsigned long claimed_interfaces;
	struct list_head list;
	struct libusb_device *dev;
	int auto_detach_kernel_driver;
	__attribute__((aligned(sizeof(void *)))) unsigned char os_priv[ZERO_SIZED_ARRAY];
};


enum {
	USBI_CLOCK_MONOTONIC,
	USBI_CLOCK_REALTIME
};


struct usbi_transfer {
	int num_iso_packets;
	struct list_head list;
	struct list_head completed_list;
	struct timeval timeout;
	int transferred;
	uint32_t stream_id;
	uint8_t state_flags;
	uint8_t timeout_flags;
	pthread_mutex_t lock;
};

enum usbi_transfer_state_flags {
	USBI_TRANSFER_IN_FLIGHT = 1U << 0,
	USBI_TRANSFER_CANCELLING = 1U << 1,
	USBI_TRANSFER_DEVICE_DISAPPEARED = 1U << 2,
};

enum usbi_transfer_timeout_flags {
	USBI_TRANSFER_OS_HANDLES_TIMEOUT = 1U << 0,
	USBI_TRANSFER_TIMEOUT_HANDLED = 1U << 1,
	USBI_TRANSFER_TIMED_OUT = 1U << 2,
};

static inline void *usbi_transfer_get_os_priv(struct usbi_transfer *transfer)
{
	assert(transfer->num_iso_packets >= 0);
	return ((unsigned char *)transfer) + sizeof(struct usbi_transfer)
	       + sizeof(struct libusb_transfer)
	       + ((size_t)transfer->num_iso_packets
		  * sizeof(struct libusb_iso_packet_descriptor));
}

struct usb_descriptor_header {
	uint8_t bLength;
	uint8_t bDescriptorType;
};

int usbi_io_init(struct libusb_context *ctx);
void usbi_io_exit(struct libusb_context *ctx);
struct libusb_device *usbi_alloc_device(struct libusb_context *ctx,
					unsigned long session_id);
struct libusb_device *usbi_get_device_by_session_id(struct libusb_context *ctx,
						    unsigned long session_id);
int usbi_sanitize_device(struct libusb_device *dev);
void usbi_handle_disconnect(struct libusb_device_handle *dev_handle);
int usbi_handle_transfer_completion(struct usbi_transfer *itransfer,
				    enum libusb_transfer_status status);
int usbi_handle_transfer_cancellation(struct usbi_transfer *transfer);
void usbi_signal_transfer_completion(struct usbi_transfer *transfer);
int usbi_parse_descriptor(const unsigned char *source, const char *descriptor,
			  void *dest, int host_endian);
int usbi_device_cache_descriptor(libusb_device *dev);
int usbi_get_config_index_by_value(struct libusb_device *dev,
				   uint8_t bConfigurationValue, int *idx);
void usbi_connect_device(struct libusb_device *dev);
void usbi_disconnect_device(struct libusb_device *dev);
int usbi_signal_event(struct libusb_context *ctx);
int usbi_clear_event(struct libusb_context *ctx);
struct usbi_pollfd {
	struct libusb_pollfd pollfd;
	struct list_head list;
};

int usbi_add_pollfd(struct libusb_context *ctx, int fd, short events);
void usbi_remove_pollfd(struct libusb_context *ctx, int fd);
int usbi_pipe(int pipefd[2]);
struct discovered_devs {
	size_t len;
	size_t capacity;
	struct libusb_device *devices[ZERO_SIZED_ARRAY];
};

struct discovered_devs *discovered_devs_append(
	struct discovered_devs *discdevs, struct libusb_device *dev);
struct usbi_os_backend {
	const char *name;
	uint32_t caps;
	int (*init)(struct libusb_context *ctx);
	void (*exit)(struct libusb_context *ctx);
	int (*set_option)(struct libusb_context *ctx, enum libusb_option option,
			  va_list args);
	int (*get_device_list)(struct libusb_context *ctx,
			       struct discovered_devs **discdevs);
	void (*hotplug_poll)(void);
	int (*wrap_sys_device)(struct libusb_context *ctx,
			       struct libusb_device_handle *dev_handle, intptr_t sys_dev);
	int (*open)(struct libusb_device_handle *dev_handle);
	void (*close)(struct libusb_device_handle *dev_handle);
	int (*get_device_descriptor)(struct libusb_device *device,
				     unsigned char *buffer, int *host_endian);
	int (*get_active_config_descriptor)(struct libusb_device *device,
					    unsigned char *buffer, size_t len, int *host_endian);
	int (*get_config_descriptor)(struct libusb_device *device,
				     uint8_t config_index, unsigned char *buffer, size_t len,
				     int *host_endian);
	int (*get_config_descriptor_by_value)(struct libusb_device *device,
					      uint8_t bConfigurationValue, unsigned char **buffer,
					      int *host_endian);
	int (*get_configuration)(struct libusb_device_handle *dev_handle, int *config);
	int (*set_configuration)(struct libusb_device_handle *dev_handle, int config);
	int (*claim_interface)(struct libusb_device_handle *dev_handle, int interface_number);
	int (*release_interface)(struct libusb_device_handle *dev_handle, int interface_number);
	int (*set_interface_altsetting)(struct libusb_device_handle *dev_handle,
					int interface_number, int altsetting);
	int (*clear_halt)(struct libusb_device_handle *dev_handle,
			  unsigned char endpoint);
	int (*reset_device)(struct libusb_device_handle *dev_handle);
	int (*alloc_streams)(struct libusb_device_handle *dev_handle,
			     uint32_t num_streams, unsigned char *endpoints, int num_endpoints);
	int (*free_streams)(struct libusb_device_handle *dev_handle,
			    unsigned char *endpoints, int num_endpoints);
	unsigned char *(*dev_mem_alloc)(struct libusb_device_handle *handle,
					size_t len);
	int (*dev_mem_free)(struct libusb_device_handle *handle,
			    unsigned char *buffer, size_t len);
	int (*kernel_driver_active)(struct libusb_device_handle *dev_handle,
				    int interface_number);
	int (*detach_kernel_driver)(struct libusb_device_handle *dev_handle,
				    int interface_number);
	int (*attach_kernel_driver)(struct libusb_device_handle *dev_handle,
				    int interface_number);
	void (*destroy_device)(struct libusb_device *dev);
	int (*submit_transfer)(struct usbi_transfer *itransfer);
	int (*cancel_transfer)(struct usbi_transfer *itransfer);
	void (*clear_transfer_priv)(struct usbi_transfer *itransfer);
	int (*handle_events)(struct libusb_context *ctx,
			     struct pollfd *fds, nfds_t nfds, int num_ready);
	int (*handle_transfer_completion)(struct usbi_transfer *itransfer);
	int (*clock_gettime)(int clkid, struct timespec *tp);
	size_t context_priv_size;
	size_t device_priv_size;
	size_t device_handle_priv_size;
	size_t transfer_priv_size;
};

extern const struct usbi_os_backend usbi_backend;
extern struct list_head active_contexts_list;
extern pthread_mutex_t active_contexts_lock;
