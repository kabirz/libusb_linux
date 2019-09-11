#ifndef LIBUSBI_H
#define LIBUSBI_H
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>
#include <poll.h>

#include "libusb.h"
#include "version.h"
#define PTR_ALIGNED __attribute__((aligned(sizeof(void *))))

/* Message logging */
#define ENABLE_LOGGING 1
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))
#define API_EXPORTED DEFAULT_VISIBILITY

/* Macro to decorate printf-like functions, in order to get
 * compiler warnings about format string mistakes.
 */
#define USBI_PRINTFLIKE(formatarg, firstvararg) \
	__attribute__((__format__ (__printf__, formatarg, firstvararg)))

#ifdef __cplusplus
extern "C" {
#endif

#define DEVICE_DESC_LENGTH	18

#define USB_MAXENDPOINTS	32
#define USB_MAXINTERFACES	32
#define USB_MAXCONFIG		8

/* Backend specific capabilities */
#define USBI_CAP_HAS_HID_ACCESS			0x00010000
#define USBI_CAP_SUPPORTS_DETACH_KERNEL_DRIVER	0x00020000

/* Maximum number of bytes in a log line */
#define USBI_MAX_LOG_LEN	1024
/* Terminator for log lines */
#define USBI_LOG_LINE_END	"\n"

/* The following is used to silence warnings for unused variables */
#define UNUSED(var)		do { (void)(var); } while(0)

#if !defined(ARRAYSIZE)
#define ARRAYSIZE(array) (sizeof(array) / sizeof(array[0]))
#endif

struct list_head {
	struct list_head *prev, *next;
};

/* Get an entry from the list
 *  ptr - the address of this list_head element in "type"
 *  type - the data type that contains "member"
 *  member - the list_head element in "type"
 */
#define list_entry(ptr, type, member) \
	((type *)((uintptr_t)(ptr) - (uintptr_t)offsetof(type, member)))

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/* Get each entry from a list
 *  pos - A structure pointer has a "member" element
 *  head - list head
 *  member - the list_head element in "pos"
 *  type - the type of the first parameter
 */
#define list_for_each_entry(pos, head, member, type)			\
	for (pos = list_entry((head)->next, type, member);		\
		 &pos->member != (head);				\
		 pos = list_entry(pos->member.next, type, member))

#define list_for_each_entry_safe(pos, n, head, member, type)		\
	for (pos = list_entry((head)->next, type, member),		\
		 n = list_entry(pos->member.next, type, member);	\
		 &pos->member != (head);				\
		 pos = n, n = list_entry(n->member.next, type, member))

#define list_empty(entry) ((entry)->next == (entry))

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
	if (list_empty(head))
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

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *mptr = (ptr);	\
	(type *)( (char *)mptr - offsetof(type,member) );})

#ifndef CLAMP
#define CLAMP(val, min, max) ((val) < (min) ? (min) : ((val) > (max) ? (max) : (val)))
#endif
#ifndef MIN
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#endif

#define TIMESPEC_IS_SET(ts) ((ts)->tv_sec != 0 || (ts)->tv_nsec != 0)

#define TIMEVAL_TV_SEC_TYPE	time_t

/* Some platforms don't have this define */
#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts)					\
	do {								\
		(tv)->tv_sec = (TIMEVAL_TV_SEC_TYPE) (ts)->tv_sec;	\
		(tv)->tv_usec = (ts)->tv_nsec / 1000;			\
	} while (0)
#endif

#ifdef ENABLE_LOGGING

void usbi_log(struct libusb_context *ctx, enum libusb_log_level level,
	const char *function, const char *format, ...) USBI_PRINTFLIKE(4, 5);

void usbi_log_v(struct libusb_context *ctx, enum libusb_log_level level,
	const char *function, const char *format, va_list args) USBI_PRINTFLIKE(4, 0);

#define _usbi_log(ctx, level, ...) usbi_log(ctx, level, __FUNCTION__, __VA_ARGS__)

#define usbi_err(ctx, ...) _usbi_log(ctx, LIBUSB_LOG_LEVEL_ERROR, __VA_ARGS__)
#define usbi_warn(ctx, ...) _usbi_log(ctx, LIBUSB_LOG_LEVEL_WARNING, __VA_ARGS__)
#define usbi_info(ctx, ...) _usbi_log(ctx, LIBUSB_LOG_LEVEL_INFO, __VA_ARGS__)
#define usbi_dbg(...) _usbi_log(NULL, LIBUSB_LOG_LEVEL_DEBUG, __VA_ARGS__)

#else /* ENABLE_LOGGING */

#define usbi_err(ctx, ...) do { (void)ctx; } while (0)
#define usbi_warn(ctx, ...) do { (void)ctx; } while (0)
#define usbi_info(ctx, ...) do { (void)ctx; } while (0)
#define usbi_dbg(...) do {} while (0)

#endif /* ENABLE_LOGGING */

#define USBI_GET_CONTEXT(ctx)				\
	do {						\
		if (!(ctx))				\
			(ctx) = usbi_default_context;	\
	} while(0)

#define DEVICE_CTX(dev)		((dev)->ctx)
#define HANDLE_CTX(handle)	(DEVICE_CTX((handle)->dev))
#define TRANSFER_CTX(transfer)	(HANDLE_CTX((transfer)->dev_handle))
#define ITRANSFER_CTX(transfer) \
	(TRANSFER_CTX(USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer)))

#define IS_EPIN(ep)		(0 != ((ep) & LIBUSB_ENDPOINT_IN))
#define IS_EPOUT(ep)		(!IS_EPIN(ep))
#define IS_XFERIN(xfer)		(0 != ((xfer)->endpoint & LIBUSB_ENDPOINT_IN))
#define IS_XFEROUT(xfer)	(!IS_XFERIN(xfer))

/* Internal abstraction for thread synchronization */
#include <pthread.h>
#include <sys/syscall.h>
extern struct libusb_context *usbi_default_context;

/* Forward declaration for use in context (fully defined inside poll abstraction) */
struct pollfd;

struct libusb_context {
#if defined(ENABLE_LOGGING) && !defined(ENABLE_DEBUG_LOGGING)
	enum libusb_log_level debug;
	int debug_fixed;
	libusb_log_cb log_handler;
#endif

	/* internal event pipe, used for signalling occurrence of an internal event. */
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

#ifdef USBI_TIMERFD_AVAILABLE
	int timerfd;
#endif

	struct list_head list;

	PTR_ALIGNED unsigned char os_priv[ZERO_SIZED_ARRAY];
};

enum usbi_event_flags {
	/* The list of pollfds has been modified */
	USBI_EVENT_POLLFDS_MODIFIED = 1U << 0,

	/* The user has interrupted the event handler */
	USBI_EVENT_USER_INTERRUPT = 1U << 1,

	/* A hotplug callback deregistration is pending */
	USBI_EVENT_HOTPLUG_CB_DEREGISTERED = 1U << 2,
};

/* Macros for managing event handling state */
#define usbi_handling_events(ctx) \
	(pthread_getspecific((ctx)->event_handling_key) != NULL)

#define usbi_start_event_handling(ctx) \
	pthread_setspecific((ctx)->event_handling_key, ctx)

#define usbi_end_event_handling(ctx) \
	pthread_setspecific((ctx)->event_handling_key, NULL)

/* Update the following macro if new event sources are added */
#define usbi_pending_events(ctx) \
	((ctx)->event_flags || (ctx)->device_close \
	 || !list_empty(&(ctx)->hotplug_msgs) || !list_empty(&(ctx)->completed_transfers))

#ifdef USBI_TIMERFD_AVAILABLE
#define usbi_using_timerfd(ctx) ((ctx)->timerfd >= 0)
#else
#define usbi_using_timerfd(ctx) (0)
#endif

struct libusb_device {
	/* lock protects refcnt, everything else is finalized at initialization
	 * time */
	pthread_mutex_t lock;
	int refcnt;

	struct libusb_context *ctx;

	uint8_t bus_number;
	uint8_t port_number;
	struct libusb_device* parent_dev;
	uint8_t device_address;
	uint8_t num_configurations;
	enum libusb_speed speed;

	struct list_head list;
	unsigned long session_data;

	struct libusb_device_descriptor device_descriptor;
	int attached;

	PTR_ALIGNED unsigned char os_priv[ZERO_SIZED_ARRAY];
};

struct libusb_device_handle {
	/* lock protects claimed_interfaces */
	pthread_mutex_t lock;
	unsigned long claimed_interfaces;

	struct list_head list;
	struct libusb_device *dev;
	int auto_detach_kernel_driver;

	PTR_ALIGNED unsigned char os_priv[ZERO_SIZED_ARRAY];
};

enum {
	USBI_CLOCK_MONOTONIC,
	USBI_CLOCK_REALTIME
};

/* in-memory transfer layout:
 *
 * 1. struct usbi_transfer
 * 2. struct libusb_transfer (which includes iso packets) [variable size]
 * 3. os private data [variable size]
 *
 * from a libusb_transfer, you can get the usbi_transfer by rewinding the
 * appropriate number of bytes.
 * the usbi_transfer includes the number of allocated packets, so you can
 * determine the size of the transfer and hence the start and length of the
 * OS-private data.
 */

struct usbi_transfer {
	int num_iso_packets;
	struct list_head list;
	struct list_head completed_list;
	struct timeval timeout;
	int transferred;
	uint32_t stream_id;
	uint8_t state_flags;   /* Protected by usbi_transfer->lock */
	uint8_t timeout_flags; /* Protected by the flying_stransfers_lock */

	pthread_mutex_t lock;
};

enum usbi_transfer_state_flags {
	/* Transfer successfully submitted by backend */
	USBI_TRANSFER_IN_FLIGHT = 1U << 0,

	/* Cancellation was requested via libusb_cancel_transfer() */
	USBI_TRANSFER_CANCELLING = 1U << 1,

	/* Operation on the transfer failed because the device disappeared */
	USBI_TRANSFER_DEVICE_DISAPPEARED = 1U << 2,
};

enum usbi_transfer_timeout_flags {
	/* Set by backend submit_transfer() if the OS handles timeout */
	USBI_TRANSFER_OS_HANDLES_TIMEOUT = 1U << 0,

	/* The transfer timeout has been handled */
	USBI_TRANSFER_TIMEOUT_HANDLED = 1U << 1,

	/* The transfer timeout was successfully processed */
	USBI_TRANSFER_TIMED_OUT = 1U << 2,
};

#define USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer)			\
	((struct libusb_transfer *)(((unsigned char *)(transfer))	\
		+ sizeof(struct usbi_transfer)))
#define LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer)			\
	((struct usbi_transfer *)(((unsigned char *)(transfer))		\
		- sizeof(struct usbi_transfer)))

static inline void *usbi_transfer_get_os_priv(struct usbi_transfer *transfer)
{
	assert(transfer->num_iso_packets >= 0);
	return ((unsigned char *)transfer) + sizeof(struct usbi_transfer)
		+ sizeof(struct libusb_transfer)
		+ ((size_t)transfer->num_iso_packets
			* sizeof(struct libusb_iso_packet_descriptor));
}

/* bus structures */

/* All standard descriptors have these 2 fields in common */
struct usb_descriptor_header {
	uint8_t bLength;
	uint8_t bDescriptorType;
};

/* shared data and functions */

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

void usbi_connect_device (struct libusb_device *dev);
void usbi_disconnect_device (struct libusb_device *dev);

int usbi_signal_event(struct libusb_context *ctx);
int usbi_clear_event(struct libusb_context *ctx);

/* Internal abstraction for poll (needs struct usbi_transfer on Windows) */
#include <unistd.h>
struct usbi_pollfd {
	/* must come first */
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
	/* A human-readable name for your backend, e.g. "Linux usbfs" */
	const char *name;

	/* Binary mask for backend specific capabilities */
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

	/* Alloc num_streams usb3 bulk streams on the passed in endpoints */
	int (*alloc_streams)(struct libusb_device_handle *dev_handle,
		uint32_t num_streams, unsigned char *endpoints, int num_endpoints);

	/* Free usb3 bulk streams allocated with alloc_streams */
	int (*free_streams)(struct libusb_device_handle *dev_handle,
		unsigned char *endpoints, int num_endpoints);

	/* Allocate persistent DMA memory for the given device, suitable for
	 * zerocopy. May return NULL on failure. Optional to implement.
	 */
	unsigned char *(*dev_mem_alloc)(struct libusb_device_handle *handle,
		size_t len);

	/* Free memory allocated by dev_mem_alloc. */
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

	/* Cancel a previously submitted transfer.
	 *
	 * This function must not block. The transfer cancellation must complete
	 * later, resulting in a call to usbi_handle_transfer_cancellation()
	 * from the context of handle_events.
	 */
	int (*cancel_transfer)(struct usbi_transfer *itransfer);

	void (*clear_transfer_priv)(struct usbi_transfer *itransfer);

	int (*handle_events)(struct libusb_context *ctx,
		struct pollfd *fds, nfds_t nfds, int num_ready);

	int (*handle_transfer_completion)(struct usbi_transfer *itransfer);

	int (*clock_gettime)(int clkid, struct timespec *tp);

#ifdef USBI_TIMERFD_AVAILABLE
	/* clock ID of the clock that should be used for timerfd */
	clockid_t (*get_timerfd_clockid)(void);
#endif

	size_t context_priv_size;
	size_t device_priv_size;
	size_t device_handle_priv_size;
	size_t transfer_priv_size;
};

extern const struct usbi_os_backend usbi_backend;

extern struct list_head active_contexts_list;
extern pthread_mutex_t active_contexts_lock;

#ifdef __cplusplus
}
#endif

#endif
