/*! @file
 * Open Questions:
 *
 * \todo Windows os handle: file handle, iocompletionport ???.
 --> Wait and talk to a Windows expert on this (e.g., Fab T.).

 * Goals of CCI:
 * - simplicity: small API (e.g., smaller/easier than verbs)
 * - portability: support multiple different underlying transports
 * - performance: preferably faster than TCP sockets, but definitely
     no slower than TCP sockets

 * \todo How do we return errors for non-zero-copy sends?  (e.g., RNR
   errors that take a while to occur -- may be long after the send has
   locally completed).  We can't necessarily return a pointer to the
   messsage that failed because the app may have overwritten it by
   then.  Possible: we could return an asynch event send error with a
   pointer to our internal buffer, with the condition that the
   internal buffer will be released when the event is returned...?

 * \todo Explain object allocation: CCI allocates everything; it may
   allocate some hidden state with it.  CCI has to clean up all
   structs, too.
*/

/* ================================================================== */
/*                                                                    */
/*                               INIT                                 */
/*                                                                    */
/* ================================================================== */

/*! \defgroup env Initialization / Environment */

/*! 
  This constant is passed in via the cci_init() function and is used
  for internal consistency checks.

  \ingroup env
 */
#define CCI_ABI_VERSION 1

/*!
  This is the first CCI function that must called; no other CCI
  functions can be invoked before this function returns successfully.

   IN abi_ver: A constant describing the ABI version that this
   application requires (one of the CCI_ABI_* values).

   IN flags: A constant describing behaviors that this application
   requires.  Currently, 0 is the only valid value.

   OUT caps: Capabilities of the underlying library:
   * THREAD_SAFETY

   Returns CCI_SUCCESS (0) on success, non-zero on failure.

   If cci_init() completes successfully, then CCI is loaded and
   available to be used in this application.  There is no
   corresponding "finalize" call.

   If cci_init() fails, an appropriate error code is returned.

   If cci_init() is invoked again with the same parameters after it
   has already returned successfully, it's a no-op.  If invoked again
   with different parameters, if the CCI implementation can change its
   behavior to *also* accomodate the new behaviors indicated by the
   new parameter values, it can return successfully.  Otherwise, it
   can return a failure and continue as if cci_init() had not been
   invoked again.

  \ingroup env
*/
int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t * caps);

/* ================================================================== */
/*                                                                    */
/*                             STATUS                                 */
/*                                                                    */
/* ================================================================== */

/*! Status codes that are returned from CCI functions.

  Note that status code names that are derived from <errno.h>
  generally follow the same naming convention (e.g., EINVAL ->
  CCI_EINVAL).  Error status codes that are unique to CCI are of the
  form CCI_ERR_<foo>.

  \ingroup env
 */
typedef enum cci_status {

	/*! Returned from most functions when they succeed. */
	CCI_SUCCESS = 0,

	/* -------------------------------------------------------------
	   General error status codes
	   ------------------------------------------------------------- */

	/*! Invalid parameter passed to CCI function call */
	CCI_EINVAL = EINVAL,

	/* ...more here, inspired from errno.h... */

	/* -------------------------------------------------------------
	   Send completion status codes
	   ------------------------------------------------------------- */

	/*! For a reliable send, this error code means that the sender did
	   not get anything back from the receiver within a timeout (no
	   ACK, no NACK, etc.).  It is unknown whether the receiver
	   actually received the message or not.

	   This error code won't occur for unreliable sends.
	 */
	CCI_ETIMEDOUT = ETIMEDOUT,

	/*! For both reliable and unreliable sends, this error code means
	   that cci_disconnect() has been invoked on the send side (in
	   which case this is an application error), or the receiver
	   replied that the receiver invoked cci_disconnect(). */
	CCI_ERR_DISCONNECTED,

	/*! For a reliable send, this error code means that a receiver
	   is reachable, the connection is connected but the receiver 
	   could not receive the incoming message during the timeout 
	   period. If a receiver cannot receive an incoming message for 
	   transient reasons (most likely out of resources), it returns 
	   an Receiver-Not-Ready NACK and drops the message.  The sender 
	   keeps retrying to send the message until the timeout expires, 

	   If the timeout expires and the last control message received
	   from the receiver was an RNR NACK, then this message is
	   completed with the RNR status.  If the connection is both
	   reliable and ordered, then all successive sends are also
	   completed in the order in which they were issued with the RNR
	   status.

	   \todo We need a discussion somewhere in the docs of exactly what
	   happens for reliables with RNR, drops, ordering, ... etc.

	   This error code will not be returned for unreliable sends.
	 */
	CCI_ERR_RNR,

	/*! the local device is gone, not coming back */
	CCI_ERR_DEVICE_DEAD,

	/*! Error returned from remote peer indicating that the address was
	   either invalid or unable to be used for access / permissions
	   reasons. */
	CCI_ERR_RMA_HANDLE,

	/*! Error returned from remote peer indicating that it does not support
	   the operation that was requested. */
	CCI_ERR_RMA_OP,
} cci_status_t;

/*!
  Returns a string corresponding to a CCI status enum.
   
  IN status: A CCI status enum.
   
  Returns a string when the status is valid; NULL otherwise.

  \ingroup env
*/
const char *cci_strerror(enum cci_status status);

/* ================================================================== */
/*                                                                    */
/*                             DEVICES                                */
/*                                                                    */
/* ================================================================== */

/*! \defgroup devices Devices */

/*! \section devices Devices
  Device types and functions.  

  \ingroup devices
   
  Before launching into detail, let's first describe the CCI system
  configuration file.  On POSIX systems, it is likely a simple
  INI-style text file; on Windows systems, it may be registry entries.
  The key thing is to support trivial namespaces and key=value pairs.

  Here is an example text config file:
  
\verbatim
# Comments are anything after the # symbols.

# Sections in this file are denoted by [section name].  Each section
# denotes a single CCI device.

[bob0] 
# The only mandated field in each section is "driver".  It indicates
# which CCI driver should be applied to this device.
driver = psm

# The priority field determines the ordering of devices returned by
# cci_get_devices().  100 is the highest priority; 0 is the lowest priority.  
# If not specified, the priority value is 50.
priority = 10

# The last field understood by the CCI core is the "default" field.
# Only one device is allowed to have a "true" value for default.  All
# others must be set to 0 (or unset, which is assumed to be 0).  If
# one device is marked as the default, then this device will be used
# when NULL is passed as the device when creating an endpoint.  If no
# device is marked as the default, it is undefined as to which device
# will be used when NULL is passed as the device when creating an
# endpoint.
default = 1

# All other fields are uninterpreted by the CCI core; they're just
# passed to the driver.  The driver can do whatever it wants with
# these values (e.g., system admins can set values to configure the
# driver).  Driver documentation should specify what parameters are
# available, what each parameter is/does, and what its legal values
# are.

# This example shows a bonded PSM device that uses both the ipath0 and
# ipath1 devices.  Some other parameters are also passed to the PSM
# driver; it assumedly knows how to handle them.

device = ipath0,ipath1
capabilities = bonded,failover,age_of_captain:52
qos_stuff = fast

# bob2 is another PSM device, but it only uses the ipath0 device.
[bob2]
driver = psm
device = ipath0

# bob3 is another PSM device, but it only uses the ipath1 device.
[bob3]
driver = psm
device = ipath1
sl = 3 # IB service level (if applicable)

# storage is a device that uses the udp driver.  Note that this driver
# allows specifying which device to use by specifying its IP address
# and MAC address -- assumedly it's an error if there is no single
# device that matches both the specified IP address and MAC
# (vs. specifying a specific device name).
[storage]
driver = udp
priority = 5
ip = 172.31.194.1
mac = 01:12:23:34:45
\endverbatim

The config file forms the basis for the device discussion, below.
*/

/*! 
  Structure representing one CCI device. A CCI device is a [section]
  from the config file, above.

  \ingroup devices
*/
typedef struct cci_device {
	/*! Name of the device from the config file, e.g., "bob0" */
	const char *name;

	/*! Human readable description string (to include newlines); should
	   contain debugging info, probably the network address of the
	   device at a bare minimum. */
	const char *info;

	/*! Array of "key=value" strings from the config file for this
	   device; the last pointer in the array is NULL. */
	const char **conf_argv;

	/*! Maximum send size supported by the device */
	uint32_t max_send_size;

	/*! Data rate per specitication: data bits per second (not the
	   signaling rate). */
	uint64_t rate;

	/*! The PCI ID of this device as reported by the OS/hardware.  All
	   values will be ((uint32_t) -1) for non-PCI devices (e.g.,
	   shared memory) */
	struct {
		uint32_t domain, bus, dev, func;
	} pci;
} cci_device_t;

/*! 
  Get an array of devices.
  
  Returns a NULL-terminated array of (struct cci_device *)'s that are
  "up".  The pointers can be copied, but the actual cci_device
  instances may not.  The array of devices is allocated by the CCI
  library; there may be hidden state that the application does not
  see.

  \param[out] devices	Array of pointers to be filled by the function. 
			Previous value in the pointer will be overwritten.

  \return CCI_SUCCESS on success.

  If cci_get_devices() succeeds, the entire returned set of data (to
  include the data pointed to by the individual cci_device
  instances) should be treated as const, and must be freed with a
  corresponding call to cci_free_devices().
  
  The order of devices returned corresponds to the priority fields in
  the devices.  If two devices share the same priority, their
  ordering in the return array is arbitrary.
  
  If cci_get_devices() fails, the value returned in devices is
  undefined.

  \ingroup devices
*/
int cci_get_devices(cci_device_t const ***devices);

/*! 
  Frees a NULL-terminated array of (cci_device_t*)'s that were
  previously allocated via cci_get_devices().

  IN devices: array of pointers previously filled in via
  cci_get_devices().

  Returns 0 on success, non-zero on failure.

  If cci_free_devices() succeeds, the data pointed to by the devices
  pointer will be stale (and should not be accessed).

  If cci_free_devices() fails, the state of the data pointed to by
  the devices parameter is undefined.

  \ingroup devices
*/
int cci_free_devices(cci_device_t const **devices);

/*====================================================================*/
/*                                                                    */
/*                            ENDPOINTS                               */
/*                                                                    */
/*====================================================================*/

/*! \defgroup endpoints Endpoints */

/*! 
  And endpoint is a set of resources associated with a single NUMA
  locality.  Buffers should be pinned by the CCI implementation to the
  NUMA locality where the thread is located who calls
  create_endpoint().

  Advice to users: bind a thread to a locality before calling
  create_endpoint().

  Sidenote: if we want to someday make endpoints span multiple NUMA
  localities, we can add a function to say "add this locality (or
  thread?) to this endpoint.

  \todo Flesh this out section better.

  Endpoints are "thread safe" by default...  Meaning multiple threads
  can call functions on endpoints simultaneously and it's "safe".  No
  guarantees are made about serialization or concurrency.

  \ingroup endpoints
 */

/*! A set of flags that describe how the endpoint should be created.

  \ingroup endpoints
 */
typedef enum cci_endpoint_flags {
	/*! For future expansion */
} cci_endpoint_flags_t;

/*! Endpoint. 

  \ingroup endpoints
*/
typedef struct cci_endpoint {
	/*! Maximum number of receive buffers on this endpoint that can be
	   loaned to the application.  When this number of buffers have
	   been loaned to the application, incoming messages may be
	   dropped. */
	uint32_t max_recv_buffer_count;
} cci_endpoint_t;

/*! OS-native handles

  \ingroup endpoints
 */
#ifdef _WIN32
typedef HANDLE cci_os_handle_t;
#else
typedef int cci_os_handle_t;
#endif

/*!
  Create an endpoint.

  IN device: A pointer to a device that was returned via
  cci_get_devices() or NULL.
  
  IN flags: Flags specifying behavior of this endpoint.
  
  OUT endpoint: A handle to the endpoint that was created.
  
  This function creates a CCI endpoint.  A CCI endpoint represents 
  a collection of local resources (such as buffers).  An endpoint 
  is associated with a device that performs the actual communication 
  (see the description of cci_get_devices(), above).
  
  The device argument can be a pointer that was returned by
  cci_get_devices() to indicate that a specific device should be used
  for this endpoint, or NULL, indicating that the system default
  device should be used.
  
  If successful, cci_create_endpoint() creates an endpoint and
  returns a pointer to it in the endpoint parameter.
  
  cci_create_endpoint() is a local operation (i.e., it occurs on
  local hardware).  There is no need to talk to name services, etc.
  To be clear, the intent is that this function can be invoked many
  times locally without affecting any remote resources.
  
  If it is desirable to bind the CCI endpoint to a specific set of
  resources (e.g., a NUMA node), you should bind the calling thread
  before calling cci_create_endpoint().
  
  Advice to users: if you want to set the send/receive buffer count
  on the endpoint, call cci_set|get_opt() after creating the
  endpoint.

  \ingroup endpoints
*/
int cci_create_endpoint(cci_device_t * device,
			int flags,
			cci_endpoint_t ** endpoint, cci_os_handle_t * fd)

/*! Destroy an endpoint.

   IN endpoint: Handle previously returned from a successful call to
   cci_create_endpoint().

   Returns CCI_SUCCESS on success.

   Successful completion of this function makes all data structures
   and state associated with the endpoint stale.  All open connections
   are closed immediately -- it is exactly as if cci_disconnect() was
   invoked on every open connection on this endpoint.

  \ingroup endpoints
 */
int cci_destroy_endpoint(cci_endpoint_t * endpoint);

/*====================================================================*/
/*                                                                    */
/*                            CONNECTIONS                             */
/*                                                                    */
/*====================================================================*/

/*! \defgroup connection Connections */

/********************/
/*                  */
/*      SERVER      */
/*                  */
/********************/

/*!
  Connection request attributes.

  Reliable connections deliver messagees once. If the packet cannot
  be delivered after a specific ammount of time, the connection is
  broken; there is no guarantee regarding which messages have been
  received successfully before the connection was broken.
  
  Connections can be ordered or unordered, but note that ordered
  unreliable connections are forbidden.  Also, note that ordering of
  RMA operations only applies to target notification, not data
  delivery.
  
  Unreliable unordered connections have no timeout.
  
  Multicast is always unreliable unordered.  Multicast connections
  are always unidirectional, send *or* receive.  If an endpoint wants
  to join a multicast group to both send and receive, it needs to
  establish two distinct connections, one for sending and one for
  receiving.

  \ingroup connection
*/
typedef enum cci_conn_attribute {
	CCI_CONN_ATTR_RO,	/*!< Reliable ordered.  Means that
				   both completions and delivery are
				   in the same order that they were
				   issued. */
	CCI_CONN_ATTR_RU,	/*!< Reliable unordered.  Means that
				   delivery is guaranteed, but both
				   delivery and completion may be in a
				   different order than they were
				   issued. */
	CCI_CONN_ATTR_UU,	/*!< Unreliable unordered (RMA
				   forbidden).  Delivery is not
				   guaranteed, and both delivery and
				   completions may be in a different
				   order than they were issued. */
	CCI_CONN_ATTR_UU_MC_TX,	/*!< Multicast send (RMA forbidden) */
	CCI_CONN_ATTR_UU_MC_RX,	/*!< Multicast recv (RMA forbidden) */
} cci_conn_attribute_t;

/*! 
  Connection request. 
  
  \ingroup connection
*/
typedef struct cci_conn_req {
	/*! Array of compatible devices */
	cci_device_t *devices[];
	/*! Number of compatible devices */
	uint32_t devices_cnt;

	/*! Pointer to connection data received with the connection request */
	const void *data_ptr;
	/*! Length of connection data */
	uint32_t data_len;

	/*! Attribute of requested connection */
	cci_conn_attribute_t attribute;
} cci_conn_req_t;

/*!
  Connection handle.
  
  \ingroup connection
*/
typedef struct cci_connection {
	/*! Maximum send size for the connection */
	uint32_t max_send_size;
	/*! Local endpoint associated to the connection */
	cci_endpoint_t *endpoint;
	/*! Attributes of the connection */
	cci_conn_attribute_t attribute;
} cci_connection_t;

/*!
  Service handle.

  JMS Fill me in
*/
typedef struct cci_service {
	/* \todo When someone implements: We can't think of anything to
	   put in here right now, but let's see what happens when someone
	   does the first implementation. */
} cci_service_t;

/*!
  Bind a service to the connection manager using specific service port.  

  It returns a service handle and an OS-specific handle that
  can be used for blocking (e.g., via POSIX poll(), select(), or
  Windows' WaitOnMultipleObjects(), or other OS-specific methods).

  If a specific service port is not required, passing "0" will
  allocate an unused one.  If the requested service poll is already
  used by another application, an error is returned.  The lowest 4096
  (?) ports are reserved for priviledged processes.

  \param[in] device	Device to bind to, can be NULL.
  \param[in] backlog	Incoming connection requests queue depth.
  \param[in,out] port	Port number used by client to identify the 
			service accepting connection requests.
  \param[out] service	Handle representing the service acception connection 
			requests through the connection manager.
  \param[out] fd	OS-specific file descriptor/handle to block on 
			incoming connection requests.

  \return CCI_SUCCESS	Service successfully bound on that device.
  \return CCI_EBUSY	The service port is already bound on that device.
   
  If you use the same service port, you get the same service, even for 
  different devices. The connection request will contain all the devices 
  that are compatible for the connection.

  \ingroup connection
*/
int cci_bind(cci_device_t * device, int backlog, uint32_t * port,
	     cci_service_t ** service, cci_os_handle_t * fd);

/*! 
  Unbind a previously-bound service.
  
  \param[in] service	Service that was previously returned from cci_bind().
  \param[in] device	Specific device to unbind from the service. If 0, 
			unbinds all devices bound to that service.
  
  \returns CCI_SUCCESS on success.

  The service could become stale if there is no more device bound to that 
  service. This does not affect established connections.

  \ingroup connection
*/
int cci_unbind(cci_service_t * service, cci_device_t * device);

/*! 
  Return the next connection request, if any.  

  \param[in] service	Service to check for incoming requests.
  \param[out] conn_req	New connection request.

  \return CCI_SUCCESS	A new connection request is available.
  \return CCI_EAGAIN	No connection request was ready.

  This function always returns immediately, even if nothing is
  available.  The application can block on the OS-specific handle
  returned by cci_bind(), if desired.

  The connection request structure contains the connection information, 
  including pointer to the connection request data.

  \ingroup connection
*/
int cci_get_conn_req(cci_service_t * service, cci_conn_req_t ** conn_req);

/*! 
  Accept a connection request and establish a connection with a specific 
  endpoint.

  \param[in] conn_req	A connection request previously returned by 
			cci_get_conn_req().
  \param[in] endpoint	The local endpoint to use for this connection. 
			It must be bound to one of the devices specified 
			in the connection request.
  \param[in,out] connection Pointer to a connection request structure.

  \return CCI_SUCCESS   The connection has been established.
  \return CCI_EINVAL    The endpoint is not bound to one of the devices 
			in the connection request.
  \return CCI_ETIMEDOUT The incoming connection request timed out 
			on the client.

  Upon success, the incoming connection request is bound to the
  desired endpoint and a connection handle is filled in.  The
  connection request handle then becomes stale.

  \ingroup connection
*/
int cci_accept(cci_conn_req_t * conn_req, cci_endpoint_t * endpoint,
	       cci_connection_t ** connection);

/*! 
  Reject a connection request.

  \param[in] conn_req	Connection request to reject.

  \return CCI_SUCCESS	Connection request has been rejected.
  \return CCI_ETIMEDOUT The incoming connection request timed out 
			on the client.

   Rejects an incoming connection request.  The connection request
   becomes stale after this function returns successfully; no further
   interaction with this connection is possible after rejecting it.
   
   \ingroup connection
 */
int cci_reject(cci_conn_req_t * conn_req);

/********************/
/*                  */
/*      CLIENT      */
/*                  */
/********************/

/*! 
  Initiate a connection request (client side).
  
  Request a connection through a connection manager on a given machine
  for a given CCI service port. The connection manager address is
  described by a Uniform Resource Identifier. The use of an URI allows
  for flexible description (IP address, hostname, etc).
  
  The connection request can carry limited 
  amount of data to be passed to the server for application-specific usage 
  (identification, authentification, etc).
  
  The connect call is always non-blocking, reliable and requires a decision 
  by the server (accept or reject), even for unreliable connection, except 
  for multicast.
  
  Multicast connections don't necessarily involve a discrete connection 
  server, they may be handled by IGMP or other distributed framework.
  
  Upon completion, an ...
  
  \param[in] endpoint	Local endpoint to use for requested connection.
  \param[in] server_uri	Uniform Resource Identifier of the server.
	The URI is flexible and can encode different values. Coma-separated 
	arguments can be added after a colon.
		- IP address: "ip://172.31.194.2"
		- Resolvable name: "ip://foo.bar.com"
		- IB LID or GID: "ib://TBD"
		- Blah id: "blah://crap0123"
		- With arguments: "ip://foo.bar.com:eth1,eth3"
  \param[in] port	The CCI port number use to identify the service on 
			the server.
  \param[in] data_ptr	Pointer to connection data to be sent in the 
			connection request (for authentification, etc).
  \param[in] data_len	Length of connection data.  Implementations must 
                        support a data_len values <= 1,024 bytes.
  \param[in] attribute	Attributes of the requested connection (reliability, 
			ordering, multicast, etc).
  \param[in] context	Cookie to be used to identify the completion through 
			an Other event.
  \param[in] flags	Currently unused.
  \param[in] timeout	NULL means forever.

  \ingroup connection

  The server_uri is used to identify/reach a specific machine (it does
  not necessarily imply a specific destination endpoint). The URIs are
  strings so that we can easily accommodate special needs. The URIs
  are typically passed by the environment, as a hostname, an IP
  address, or whatever makes sense to identify a remote machine. The
  main part of the URI is device independent, it's only the
  identification of the remote machine. The arguments are
  device-specific. On the client side, the device to use is dictated
  by the local endpoint. On the server side, multiple devices can be
  used for the connection, depending on connectivity and arguments
  from the client.
*/
/* QUESTION: data is cached or not ? */
int cci_connect(cci_endpoint_t * endpoint, char *server_uri, uint32_t port,
		void *data_ptr, uint32_t data_len,
		cci_conn_attribute_t attribute,
		void *context, int flags, struct timeval *timeout);

/*!
  Tear down an existing connection. 

  Operation is local, remote side is not notified. From that point, 
  both local and remote side will get a DISCONNECTED communication error 
  if sends are initiated on  this connection.

  \param[in] connection	Connection to sever.

  \ingroup connection
 */
int cci_disconnect(cci_connection_t * connection);

/*====================================================================*/
/*                                                                    */
/*                 ENDPOINTS / CONNECTIONS OPTIONS                    */
/*                                                                    */
/*====================================================================*/

/*! Handle defining the scope of an option */
typedef union cci_opt_handle {
	/*! Endpoint */
	cci_endpoint_t *endpoint;
	/*! Connection */
	cci_connection_t *connection;
} cci_opt_handle_t;

/*! Level defining the scope of an option */
typedef enum cci_opt_level {
	/*! Flag indicating that the union is an endpoint */
	CCI_OPT_LEVEL_ENDPOINT,
	/*! Flag indicating that the union is a connection */
	CCI_OPT_LEVEL_CONNECTION,
} cci_opt_level_t;

/*! Name of options */
typedef enum cci_opt_name {
	/*! Max header size (in bytes) on the endpoint, for both sends and
	   RMA operations. */
	CCI_OPT_ENDPT_MAX_HEADER_SIZE,	/* get */

	/*! default send timeout for all new connections */
	CCI_OPT_ENDPT_SEND_TIMEOUT,	/* set/get */

	/*! How many receiver buffers on the endpoint.  It is the max
	   number of messages the CCI layer can receive without dropping.  */
	CCI_OPT_ENDPT_RECV_BUF_COUNT,	/* set/get */

	/*! How many send buffers on the endpoint.  It is the max number of
	   pending messages the CCI layer can buffer before failing or
	   blocking (depending on reliability mode). */
	CCI_OPT_ENDPT_SEND_BUF_COUNT,	/* set/get */

	/*! The "keepalive" timeout is to prevent a client from connecting
	   to a server and then the client disappears without the server
	   noticing.  If the server never sends anything on the connection,
	   it'll never realize that the client is gone, but the connection
	   is still consuming resources.  But note that keepalive timers
	   apply to both clients and servers.

	   The keepalive timeout is expressed in microseconds.  If the
	   keepalive timeout value is set:

	   - If no traffic at all is received on a connection within the
	   keepalive timeout, the CCI_EVENT_KEEPALIVE_TIMEOUT event is
	   raised on that connection.

	   - The CCI implementation will automatially send control
	   hearbeats across an inactive (but still alive) connection to
	   reset the peer's keepalive timer before it times out.

	   If a keepalive event is raised, the keepalive timeout is set to
	   0 (i.e., it must be "re-armed" before it will timeout again),
	   but the connection is *not* disconnected.  Recovery decisions
	   are up to the application; it may choose to disconnect the
	   connection, re-arm the keepalive timeout, etc. */
	CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT,	/* set/get */

	/*! reliable send timeout in microseconds */
	CCI_OPT_CONN_SEND_TIMEOUT,	/* set/get */
} cci_opt_name_t;

/*! 
  JMS Fill me in

  Note that the set may fail if the CCI implementation cannot
  actually set the value.
*/
int cci_set_opt(cci_opt_handle_t * handle, cci_opt_level_t level,
		cci_opt_name_t name, const void *val, int len);

/*! JMS Fill me in */
int cci_get_opt(cci_opt_handle_t * handle, cci_opt_level_t level,
		cci_opt_name_t name, void **val, int *len);

/* ================================================================== */
/*                                                                    */
/*                           EVENTS                                   */
/*                                                                    */
/* ================================================================== */

/*! \defgroup events Events */

/*!
  Send event.
  
  A completion struct instance is returned for each cci_send() that
  requested a completion notification.
  
  On a reliable connection, a sender will generally complete a send
  when the receiver replies for that message.  Additionaly, an error 
  status may be returned (UNREACHABLE, DISCONNECTED, RNR).
  
  On an unreliable connection, a sender will return CCI_SUCCESS upon
  local completion (i.e., the message has been queued up to some lower
  layer -- there is no guarantee that it is "on the wire", etc.).
  Other send statuses will only be returned for local errors.
  
  The number of fields in this struct is intentionally limited in
  order to reduce costs associated with state storage, caching,
  updating, copying.  For example, there is no field pointing to the
  endpoint used for the send because it can be obtained from the
  cci_connection, or through the endpoint passed to the
  cci_get_event() call.
  
  If it is desirable to match send completions with specific sends
  (it usually is), it is the responsibility of the caller to pass a
  meaningful context value to cci_send().
  
  The ordering of fields in this struct is intended to reduce memory
  holes between fields.

  \ingroup events
*/
typedef struct cci_event_send {
	/*! Connection that the send was initiated on. */
	cci_connection_t *connection;

	/*! Context value that was passed to cci_send() */
	void *context;

	/*! Result of the send. */
	cci_status_t status;
} cci_event_sent_t;

/*! 
  Receive event.
  
  A completion struct instance is returned for each message received.
  
  The number of fields in this struct is intentionally limited in
  order to reduce costs associated with state storage, caching,
  updating, copying.  For example, there is no field pointing to the
  endpoint because it can be obtained from the cci_connection or
  through the endpoint passed to the cci_get_event() call.
  
  The ordering of fields in this struct is intended to reduce memory
  holes between fields.

  \ingroup events
*/
typedef struct cci_event_recv {
	/*! The length of the header part of the message (in bytes). 
	   This value may be 0. */
	uint32_t header_len;

	/*! The length of the data part of the message (in bytes). 
	   This value may be 0. */
	uint32_t data_len;

	/*! Pointer to the header part of the received message.  The pointer
	   always points to an address that is 8-byte aligned, unless
	   (header_len == 0), in which case the value is undefined. */
	void *const header_ptr;

	/*! Pointer to the data part of the received message.  The pointer
	   always points to an address that is 8-byte aligned, unless
	   (header_len == 0), in which case the value is undefined. */
	void *const data_ptr;

	/*! Connection that this message was received on. */
	cci_connection_t *connection;
} cci_event_recv_t;

/*! Other event
    JMS Fill me in

  \ingroup events
 */
typedef struct cci_event_other {
	/*! Context value */
	void *context;
} cci_event_other_t;

/*! JMS Fill me in

  \ingroup events
 */
typedef enum cci_event_type {

	CCI_EVENT_NONE,

	CCI_EVENT_SEND,

	CCI_EVENT_RECV,

	/*! A new outgoing connection was successfully accepted at the
	   peer; a connection is now available for data transfer. */
	CCI_EVENT_CONNECT_SUCCESS,

	/*! A new outgoing connection did not complete the accept/connect
	   handshake with the peer in a finite time.  CCI has therefore
	   given up attempting to continue to create this connection. */
	CCI_EVENT_CONNECT_TIMEOUT,

	/*! A new outgoing connection was rejected by the server. */
	CCI_EVENT_CONNECT_REJECTED,

	/*! This event occurs when the keepalive timeout has expired (see
	   CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT for more details). */
	CCI_EVENT_KEEPALIVE_TIMEOUT,

	/*! A device on this endpoint has failed.

	   \todo JMS What exactly do we do here?  Do all handles
	   (connections, etc.) on the endpoint become stale?  What about
	   sends that are in-flight -- do we complete them all with an
	   error?  And so on. */
	CCI_EVENT_ENDPOINT_DEVICE_FAIL,
} cci_event_type_t;

/*! 
  Generic event
  
  This is the union of Send, Recv and Other events.

  \ingroup events
*/
typedef struct cci_event {
	/*! Type of the event */
	cci_event_type_t type;

	union {
		cci_event_send_t send;
		cci_event_recv_t recv;
		cci_event_other_t other;
	} info;
} cci_event_t;

/********************/
/*                  */
/*  Event handling  */
/*                  */
/********************/

/*! JMS Fill me in 

  \todo From Patrick: This function is for windows. The default way to
   do Object synchronization in Windows is to have the kernel
   continuously notify the Object in user-space. On Unixes, we can
   catch the call to poll to arm the interrupt, but we can't on
   Windows, so we have a function for that.  Since we are not Windows
   gurus, we decided to freeze it until we ask a pro about it.

  \ingroup events
*/
int cci_arm_os_handle(cci_endpoint_t * endpoint, int flags);

/*!
  Get the next available CCI event.

  This function never blocks; it polls instantly to see if there is
  any pending event of any type (send completion, receive, or other 
  events -- errors, incoming connection requests, etc.).  If you want to
  block, use the OS handle to use your OS's native blocking mechanism
  (e.g., select/poll on the POSIX fd).  This also allows the app to
  busy poll for a while and then OS block if nothing interesting is
  happening.  The default OS handle returned when creating the
  endpoint will return the equivalent of a POLL_IN when any event is
  available.
  
  This function borrows the buffer associated with the event; it must
  be explicitly returned later via cci_return_event().

  \param[in] endpoint	Endpoint to poll for a new event.
  \param[in] event	New event, if any.
  \param[in] flags 
	- CCI_PE_SEND_EVENT
	- CCI_PE_RECV_EVENT
	- CCI_PE_OTHER_EVENT
	- CCI_PE_I_SET_THE_DATA_BUFFER_PLEASE_COPY
   Flag value of 0 means (CCI_PE_SEND_EVENT | CCI_PE_RECV_EVENT |
   CCI_PE_OTHER_EVENT).

   To discuss:

   - it may be convenient to optionally get multiple OS handles; one
     each for send completions, receives, and "other" (errors,
     incoming connection requests, etc.).  Should that be part of
     endpoint creation?  If we allow this concept, do we need a way to
     pass in a different CQ here to get just those types of events?

   - How do we have CCI-implementation private space in the event --
     bound by size?  I.e., how/who determines the max inline data
     size?

  \ingroup events
*/
int cci_get_event(cci_endpoint_t * endpoint,
		  cci_event_t ** const event, uint32_t flags);

/*!
  This function returns the buffer associated with an event that was
  previously obtained via cci_get_event().  The data buffer associated
  with the event will immediately become stale to the application.

  Events may be returned in any order; they do not need to be returned
  in the same order that cci_poll_event() issued them.  All events
  must be returned, even send completions and "other" events -- not
  just receive events.  However, it is possible (likely) that
  returning send completion and "other" events will be no-ops.

  \todo What to do about hardware that cannot return buffers out of
     order?  Is the overhead of software queued returns (to effect
     in-order hardware returns) acceptable?

  \ingroup events
*/
int cci_return_event(cci_endpoint_t * endpoint, cci_event_t * event);

/* ================================================================== */
/*                                                                    */
/*                        COMMUNICATIONS                              */
/*                                                                    */
/* ================================================================== */

/*! \defgroup communications Communications */

/*! 
  Send a short message.

  am_max_size maximum, no order guaranteed, completion is local.

  Two segments for Header and Data.  When CCI_FLAG_ASYNC is used and
  the call returns, data has been buffered.

  \param[in] connection	Connection (destination/reliability).
  \param[in] header_ptr	Pointer to local header segment.
  \param[in] header_len	Length of local header segment (limited to 32 bytes).
  \param[in] data_ptr	Pointer to local data segment.
  \param[in] data_len	Length of local data segment (limited to max send size).
  \param[in] context	Cookie to identify the completion through a Send event 
			when non-blocking.
  \param[in] flags      Optional flags: CCI_FLAG_BLOCKING,
                        CCI_FLAG_NO_COPY, CCI_FLAG_SILENT.  These flags
                        are explained below.

  \todo When someone implements: it would be nice to have a way for an
  MPI implementation to have a progress thread for long messages.
  This progress thread would only "wake up" for the rendezvous
  messages that preceed RMA operations -- short/eager messages go the
  normal processing path (that don't force a wakeup of the progression
  thread).  Patrick proposes two ways: 1. use a distinct connection
  (to a different endpoint) and block on the OS handle from second
  endpoint in the progression thread.  2. define a sleep function that
  returns only when a message with CCI_FLAG_WAKE is received.

  \ingroup communications

  The send will complete differently in reliable and unreliable
  connections:

  * Reliable: only when remote side ACKs complete delivery -- but not
    necessary consumption (i.e., remote completion).
  * Unreliable: when the buffer is re-usable (i.e., local completion).

  When cci_send() returns, the buffer is re-usable by the application.

  If the CCI_FLAG_BLOCKING flag is specified, cci_send() will _also_
  block until the send completion has occurred.  In this case, there
  is no event returned for this send via cci_get_event(); the send
  completion status is returned via cci_send().

  If the CCI_FLAG_NOCOPY is specified, the application is
  indicating that it does not need the buffer back until the send
  completion occurs (which is most useful when CCI_FLAG_BLOCKING is
  _not_ specified).  The CCI implementation is therefore free to use
  "zero copy" types of transmission with the buffer -- if it wants to.

  CCI_FLAG_SILENT means that no completion will be generated for
  non-CCI_FLAG_BLOCKING sends.  For reliable ordered connections,
  since completions are issued in order, the completion of any
  non-SILENT send directly implies the completion of any previous
  SILENT sends.  For unordered connections, completion ordering is not
  guaranteed -- it is *not* safe to assume that application protocol
  semantics imply specific unordered SILENT send completions.  The
  only ways to know when unordered SILENT sends have completed (and
  that the local send buffer is "owned" by the application again) is
  either to close the connection or issue a non-SILENT send.  The
  completion of a non-SILENT send guarantees the completion of all
  previous SILENT sends.  
*/
int cci_send(cci_connection_t * connection,
	     void *header_ptr, uint32_t header_len,
	     void *data_ptr, uint32_t data_len, void *context, int flags);

/*! JMS Fill me in

  \ingroup communications

  \todo When someone implements: is the array of data_ptrs/data_lens
        good?  Or should we use some kind of iovec?  (keep in mind
        that iovec is not standard POSIX)

  \todo JMS The passed data_ptrs/data_lens have to be buffered, just
        like the header.  The rationale is safety of scope,
        consistency, and ease of use.  The assumption is that the
        header and data_ptrs/data_lens are bounded and relatively
        small.  Max header length is already an endpoint GET opt -- do
        we need another GET opt for the max length of the
        data_ptrs/data_lens arrays?  I think so. */
*/int cci_sendv(cci_connection_t * connection,
		void *header_ptr, uint32_t header_len,
		char **data_ptrs, int *data_lens,
		uint segment_cnt, void *context, int flags);

/* RMA Area operations */

/*! JMS Fill me in

  The intent is that this function is invoked frequently -- "just
  register everything" before invoking RMA operations.

  In the best case, the implementation is cheap/fast enough that the
  invocation time doesn't noticeably affect performance (e.g., MX and
  PSM).  If the implementation is slow (e.g., IB/iWARP), this function
  should probably have a registration cache so that at least repeated
  registrations are fast.

  \ingroup communications
*/
int cci_rma_register(cci_endpoint_t * endpoint, void *start,
		     uint64_t length, uint64_t * rma_handle);

/*! \private

  This data structure should map to the native scatter/gather list
  that is used down in the kernel.

  \ingroup communications
 */
typedef struct cci_sg {
	/* JMS is this right?  Is it different than cci_iovec_t? */
	uint64_t address;
	uint32_t length;
} cci_sg_t;

/*! \private

  This is just like cci_rma_register(), but it is to be used in the
  kernel only.

  JMS Fill me in

  \ingroup communications
 */
int cci_rma_register_phys(cci_endpoint_t * endpoint,
			  cci_sg_t * sg_list, uint32_t sg_cnt,
			  uint64_t * rma_handle);

/*! JMS Fill me in

  \ingroup communications
 */
int cci_rma_deregister(uint64_t rma_handle);

/*! 
  Perform a RMA operation on remote RMA area.
  
  Local RMA area is not required, local data may be copied or corresponding 
  RMA area may be looked up (cache). No order guaranteed on data delivery 
  (no last-byte-written-last), but order is guaranteed between data delivery 
  and remote recv event (if any). Completion is local, fence/order is remote.
  Remote recv event only if (header_len != 0).

  \param[in] connection	Connection (destination/reliability).
  \param[in] header_ptr	Pointer to local header segment.
  \param[in] header_len	Length of local header segment (limited to 32 bytes)
  \param[in] local_handle	Handle of the local RMA area.
  \param[in] remote_offset	Offset in the local RMA area.
  \param[in] remote_handle	Handle of the remote RMA area.
  \param[in] remote_offset	Offset in the remote RMA area.
  \param[in] data_len	Length of local data segment (limited to max AM size).
  \param[in] context	Cookie to identify the completion through a Send event 
			when non-blocking.
  \param[in] flags	Optional flags:
	- CCI_FLAG_BLOCKING: blocking call (see cci_send() for details).
	- CCI_FLAG_READ: move data from remote to local memory.
	- CCI_FLAG_WRITE: move data from local to remote memory
	- CCI_FLAG_FENCE: wait for all previous RMA operations to complete 
	before performing this operation and all following.
	- CCI_FLAG_SILENT: generates no completion event (see cci_send() 
        for details).

  \ingroup communications

  FIXME: READ may not be performance efficient
*/
int cci_rma(cci_connection_t * connection,
	    void *header_ptr, uint32_t header_len,
	    uint64_t local_handle, uint64_t local_offset,
	    uint64_t remote_handle, uint64_t remote_offset,
	    uint64_t data_len, void *context, int flags);
