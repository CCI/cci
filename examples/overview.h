/* ================================================================== */
/*                                                                    */
/*                             OVERVIEW                               */
/*                                                                    */
/* ================================================================== */

/*!  \mainpage CCI: The Common Communication Interface

\section intro Introduction

Over the years, many networking application programming interfaces
(APIs) have be developed. The most widely used is the BSD Sockets
interface due to its implementation on nearly all hardware. Designed
to provide an interface for TCP, the Sockets interface does not allow
applications to take advantage of newer hardware and the features that
they provide. These features include remote direct memory access (RDMA),
operating system (OS) bypass, "zero-copy" support, one-sided operations,
and asynchronous operations.

Many different APIs evolved to expose these features such as the Virtual
Interface Architecture (VIA), OpenFabrics Verbs, Myrinet Express (MX), and
Portals. None have had the widespread adoption that Sockets has had.
Application developers are therefore forced to make substantial
tradeoffs in the selection of a user-level network interface for their
network-based applications. While the use of BSD Sockets guarantees
portability across nearly every type of existing network, the emulation
of the Sockets API over an underlying network-native software API can
substantially limit both performance and scalability. On the other hand,
the use of a native networking API may satisfy performance and
scalability requirements, but limit the application’s portability to
future platforms.

CCI balances the needs of portability and simplicity while preserving
the performance capabilities of advanced networking technologies. In
designing CCI, we have drawn upon prior research with a variety of
low-level networking interfaces as well as our experience in working
directly with application developers in the use of these APIs. Whenever
possible, we adhered to our primary goal of simplicity in order to
foster wide-spread adoption, yet preserving both performance and
portability.

\section design Design Goals

In setting out to design a new communication’s interface, we had several
goals in mind: portability, simplicity, performance, scalability, and
robustness.

\subsection portability Portability

Application and middleware developers do not have the resources to
continuously port their code on different communication interfaces.
Selecting a vendor-specific API introduces lock-in and reduces future
migration options. At the same time, vendors do not have the resources
to properly support a large set of middleware.  BSD Sockets and MPI both
provide this high-level of portability. For any new communication
interface to gain acceptance in the broader community, it needs to
provide a similar breadth of implementations on currently available
hardware, by supporting the semantics that are common to most vendor
APIs.

\subsection simplicity Simplicity

Simplicity is paramount to the success of a programming interface.
Critical mass cannot be reached by limiting the targeted audience to a
few networking experts. However, ease of use involves many elements
beyond just expertise. Code size is a common, albeit subjective, metric
used to compare programming interfaces. The rationale is that larger
codes are harder to debug and maintain. For example, an analysis of the
Open MPI version 1.4.3 implementation shows substantial differences
between the seven supported communication APIs (excluding self and
shared memory). The total lines of code of each Byte Transfer Layer
(BTL) for various APIs include:

 - Elan 1,656
 - MX 2,333
 - Portals 2,469
 - GM 2,779
 - Sockets (TCP) 4,192
 - UDAPL 6,208
 - OpenIB (Verbs) 21,574

The Verbs BTL is the largest, five times the size of the TCP sockets
BTL, third largest, and 8 to 13 times larger than the BTLs of the vendor
interfaces.  Another indicator of complexity is the number of functions
available.  Choice is good but too much choice is worse. Fortunately,
software programmers are efficient at reducing overly complex interfaces
to a minimum set of useful semantics. For example, MPI specifies over
300 functions but the vast majority of MPI applications only use a
fraction of them.

Similarly, relative simplicity was the main drive behind the wide
adoption of the BSD Socket interface. A communication interface should
aspire to find the right balance between richness of semantics and ease
of use.

\subsection performance Performance

Performance is major drive for innovation in networking, from HPC to
Cloud Computing. All modern network technologies leverage common
techniques developed in the last two decades: OS-bypass, zero-copy,
one-sided, and asynchronous operations. To deliver the best performance,
a communication interface should present semantics that can efficiently
leverage all these techniques as provided by modern high-speed networks.

\subsection scalability Scalability

Projections for leadership scale systems in HPC include hundreds of
thousands of nodes and millions of cores. In the commercial space, Cloud
Computing data centers are fast approaching these levels. In this
context, scalability is an important requirement. The time and space
overhead of a scalable communication interface should not grow linearly
with the number of communicating partners. BSD Sockets are inefficient
in both dimensions, as buffers and file handles are allocated for each
new socket. Through adaptive socket buffering and use of epoll(),
Sockets implementations have so far managed to reasonably handle large
number of connections. MPI is inherently more scalable and it has
successfully been deployed on large HPC machines. However, it is not
clear if MPI in its present form can efficiently scale to millions of
cores.  Scalability of the Verbs interface was originally quite poor due
to its Queue Pair model. MPI implementations used various techniques
such as connection on demand and dynamic buffer management to work
around the QPs memory footprint problem. Scalability was further
improved with the addition of Shared Receive Queues (SRQ), but distinct
QPs are still required on the send side. To address the Cloud Computing
and leadership class HPC requirements, a communication interface should
aim for constant buffer and polling overhead, independently of the
number of nodes in the fabric.

\subsection robustness Robustness

Hardware and software failures occur frequently, often proportional with
the size of the system. As system sizes continue to increase, ignoring
such failures will no longer be an option. Most MPI implementations
currently abort on failures that an application might otherwise
tolerate. To address this, there have been several efforts aimed at
designing fault-tolerant MPI libraries and adding fault recovery to the
MPI specification. Thus far these efforts have had limited success. The
loose semantic about status completions was actually a benefit in making
MPI a simpler interface, developers would send messages and trust MPI
to always deliver them. Unfortunately, real-world applications
eventually had to implement checkpoint/restart functionality to tolerate
system faults and it is the only practical solution available today on
large HPC systems today. Both Sockets and Verbs fare better than MPI on
this issue. They use connections to represent the state of communication
channels without reliance on a single consistent distributed process
space (MPI_COMM_WORLD). Connections provide a simplified model for
robustness; they contain faults and allow for their recovery by
resetting the state of the affected communication channels.
Unfortunately, both Sockets and Verbs associate buffers to a connection,
which negatively affects scalability. A robust and scalable
communication interface should provide connection-oriented semantics
without per-connection resources.

Communication reliability is often seen as a way to improve overall
robustness. For some applications such as Media Content Delivery (IPTV),
Financial Trading (HFT) or system-health monitoring, the provided
reliability may be incompatible with their timing requirements.
Furthermore, the most scalable multicast implementations are unreliable.
For these reasons, a large share of applications use unreliable
connections. A communication interface should provide different levels
of connection reliability, as well as support for multicast.

\section api The CCI Interface

In this section, we provide a brief overview of the CCI API to allow us
to discuss how CCI can meet the goals outlined above.

\subsection ini Initialization

Before calling any function, the application must call cci_init(). The
application may call cci_init() multiple times with different
parameters. The application then optionally calls cci_get_devices() to
obtain an array of available devices. The devices are parsed from a
config file and each device has a name, an array keyword/value strings,
a maximum send size in bytes, and PCI information if needed. Each
device’s maximum send size is equivalent to the network MTU (less wire
headers). When no more communication is needed, the application calls
cci_finalize().

\subsection endpts Communication Endpoints

All communication in CCI revolves around an endpoint. A single endpoint
can communicate with any number of peers.

Each endpoint has some number of device-sized buffers available for
sending and receiving small, unexpected messages. The application calls
cci_create_endpoint() and cci_destroy_endpoint(), respectively, to
obtain or release an endpoint. The application may alter the number of
send and/or receive buffers using cci_get_opt() and cci_set_opt().

The endpoint provides a context pointer for the application to use. The
application may use the context pointer to provide access to additional
state allocated by the application related to that endpoint.

\subsection evts Event Handling

CCI is inherently asynchronous and all communication functions only
initiate communication. When a communication completes, it generates an
event.  There are many event types: CCI_EVENT_SEND, CCI_EVENT_RECV,
CCI_EVENT_CONNECT_REQUEST, etc.

An application can poll for an event with cci_get_event(), which returns
an event structure of which the contents vary depending on the event’s
type. When a process is finished with an event, it uses
cci_return_event() to release it resources, if any, back to CCI.

In  addition    to  returning   an  endpoint, cci_create_endpoint() also
returns an operating system-specific handle that can be passed to
\c select() or other OS functions to allow blocking until an event is
available.

\subsection conns Connections

CCI defines a connection struct which includes the maximum send size
negotiated by the two instances of CCI, a pointer to the owning
endpoint, the connection attribute, and a context pointer.

As mentioned above, some applications may need reliable delivery while
others may not. Among applications needing reliable delivery, some may
need in-order completion (e.g. traditional SOCK_STREAM semantics) and
others may accept out-of-order completion as long as communications are
initiated in-order (e.g. MPI point-to-point). Typically, most networks
can provide higher performance for unordered versus ordered connections.

In order to provide applications with the level of service appropriate
for their needs, CCI provides multiple types of connection attributes:

 - Reliable with Ordered completion (RO)
 - Reliable with Unordered completion (RU)
 - Unreliable with Unordered completion (UU)
 - Unreliable with Unordered completion with multicast send (UU_MC_TX)
 - Unreliable with Unordered completion with multicast receive (UU_MC_RX)

If a process needs a mix of types, it is allowed to open multiple
connections to the other process.

\subsection conn_est Connection Establishment

CCI provides a client/server semantic for connection establishment.
Every open endpoint is able to initiate and receive connection
requests.

To initiate a connection, the client calls cci_connect() with parameters
including an endpoint, a string URI for the server, optionally a pointer
to a limited sized payload and its length, the connection attribute, a
pointer to an optional application context, and a timeout.

The server polls for events which may include connection requests. When
a connection request event is returned, it includes a pointer to the
application payload and its length if the client sent it, and the
requested connection attribute.

The server then calls either cci_accept() or cci_reject(). The
cci_accept() call will initiate the accept portion of the connection
handshake. When the handshake is complete, the server will get a
CCI_EVENT_ACCEPT with a status of CCI_SUCCESS and the new connection
pointer or the status will indicate why the accept failed and the
connection pointer will not be valid. The client gets an
CCI_EVENT_CONNECT event with a status of CCI_SUCCESS, the context passed
to cci_connect(), and the new connection pointer.  If the server calls
cci_reject(), the client gets a CCI_EVENT_CONNECT event with a status of
CCI_ECONNREFUSED and the context passed to cci_connect().  On the
server, the connection request event must then be returned using
cci_return_event() just like every other event. If the server does not
reply within the timeout set in the client’s cci_connect(), the client
gets an CCI_EVENT_CONNECT event with a status of CCI_ETIMEDOUT and the
context passed to cci_connect().  When a process no longer needs a
connection, it can call cci_disconnect().

\subsection msgs Messages

Once the connection is established, the two processes can start
communicating. CCI provides two methods, Messages (MSG) and remote
memory access (RMA), which we discuss in the \ref RMA section.

CCI MSGs have a maximum size that is device dependent. Ideally, the
size is equal to the link MTU (less wire headers). The driving idea to
limiting the message size to a single MTU is that future networks may
have many paths through the network due to fabrics with high-radix
switches and/or NICs with multiple ports connected to redundant switches
for fault-tolerance.  Limiting the MSG size limited to a single MTU
vastly simplifies the requirements for message completion — either it
arrives or it does not.

On receipt of a MSG, CCI returns an event of type CCI_EVENT_RECV.  The
application can get the event and hold it without blocking CCI from
continuing to service other communications.

The cci_send() parameters include the connection, a data pointer and
length, an application context pointer, and flags. The pointer may be
NULL.  The context pointer is returned in the CCI_EVENT_SEND completion
event and can be used to allow the application to retrieve its internal
state.

The optional flags parameter can accept the following:

 - CCI_FLAG_BLOCKING which means that the send should not return until
   the send completes.  The send completion status is passed in the
   function’s return value.

 - CCI_FLAG_NO_COPY is a hint to CCI that the application does not need
   the buffer back until the send completes and is free to use zero-copy
   methods if supported.

 - CCI_FLAG_SILENT indicates that the process does not want a completion
   event for this send.

On the receiver, a call to cci_get_event() returns a CCI_EVENT_RECV
event which includes a pointer to the data, its length, and a pointer to
the connection. The receiving process can choose to simply inspect the
data in-place, modify the data in-place and send it to another process,
or copy it out if it needs to keep the data long-term.  When the process
no longer needs the buffer, it releases it back to CCI with
cci_return_event(). It should be noted that if the application does not
process CCI_EVENT_RECV events and return them to CCI fast enough, that
CCI may still need to drop incoming messages.

CCI also provides cci_sendv() that takes an array of data pointers and
an array of lengths instead of the just the one data pointer and length
in cci_send(). Lastly, CCI does not require memory registration for
sending or receiving MSGs.

\anchor RMA
\subsection rma Remote Memory Access

Clearly, MSGs limited to a single MTU will not meet the needs of all
applications. Applications such as file systems which need to move
large, bulk messages need much more. To accommodate them, CCI also
provides remote memory access (RMA). RMA transfers are only allowed on
reliable connections.

Before using RMA, the process needs to explicitly register the memory.
CCI provides cci_rma_register() which takes a pointer to the endpoint,
the start of the region to be registered, the length of the region, and
flags indicating if CCI should READ or WRITE or both access. The
function returns a RMA handle. When a process no longer needs to RMA in
to or out of the region, it passes the handle to cci_rma_deregister().

For a RMA transfer to take place, both processes must register their
local memory and they need to pass the handle of the target process to
the initiator process using one or more MSGs.

The cci_rma() call takes the connection pointer, an optional MSG
pointer and length, the local RMA handle and offset, the remote RMA
handle and offset, the transfer length, an application context
pointer, and a set of flags.

If the MSG pointer and length are set, the initiator will send a
completion message to the target that arrives as an MSG with the data.

The flag options include:

 - CCI_FLAG_BLOCKING (see cci_send())
 - CCI_FLAG_SILENT (see cci_send())
 - CCI_FLAG_READ allows data to move from remote to local memory.
 - CCI_FLAG_WRITE allows data to move from local to remote memory.
 - CCI_FLAG_FENCE ensures that all previous RMA operations to complete
   remotely before this operation and all following RMA operations.

CCI does not guarantee delivery order within an operation (i.e. no
last-byte-written-last mandate), but order is guaranteed between data
delivery and the remote receive event if the MSG is specified.

*/
