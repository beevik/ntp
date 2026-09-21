[![GoDoc](https://godoc.org/github.com/beevik/ntp?status.svg)](https://godoc.org/github.com/beevik/ntp)
[![Go](https://github.com/beevik/ntp/actions/workflows/go.yml/badge.svg)](https://github.com/beevik/ntp/actions/workflows/go.yml)

ntp
===

The ntp package is an implementation of a Simple NTP (SNTP) client based on
[RFC 5905](https://tools.ietf.org/html/rfc5905). It allows you to connect to
a remote NTP server and request information about the current time.


## Querying the current time

If all you care about is the current time according to a remote NTP server,
simply use the `Time` function:
```go
time, err := ntp.Time("0.beevik-ntp.pool.ntp.org")
```


## Querying time synchronization data

To obtain the current time as well as some additional synchronization data,
use the [`Query`](https://godoc.org/github.com/beevik/ntp#Query) function:
```go
response, err := ntp.Query("0.beevik-ntp.pool.ntp.org")
time := time.Now().Add(response.ClockOffset)
```

The [`Response`](https://godoc.org/github.com/beevik/ntp#Response) structure
returned by `Query` includes the following information:
* `ClockOffset`: The estimated offset of the local system clock relative to
  the server's clock. For a more accurate time reading, you may add this
  offset to any subsequent system clock reading.
* `Time`: The time the server transmitted its response, according to its own
  clock.
* `RTT`: An estimate of the round-trip-time delay between the client and the
  server.
* `Precision`: The precision of the server's clock reading.
* `Stratum`: The server's stratum, which indicates the number of hops from the
  server to the reference clock. A stratum 1 server is directly attached to
  the reference clock. If the stratum is zero, the server has responded with
  the "kiss of death" and you should examine the `KissCode`.
* `ReferenceID`: A unique identifier for the consulted reference clock.
* `ReferenceTime`: The time at which the server last updated its local clock setting.
* `RootDelay`: The server's aggregate round-trip-time delay to the stratum 1 server.
* `RootDispersion`: The server's estimated maximum measurement error relative
  to the reference clock.
* `RootDistance`: An estimate of the root synchronization distance between the
  client and the stratum 1 server.
* `Leap`: The leap second indicator, indicating whether a second should be
  added to or removed from the current month's last minute.
* `MinError`: A lower bound on the clock error between the client and the
  server.
* `KissCode`: A 4-character string describing the reason for a "kiss of death"
  response (stratum=0).
* `Poll`: The maximum polling interval between successive messages to the
  server.

The `Response` structure's [`Validate`](https://godoc.org/github.com/beevik/ntp#Response.Validate)
function performs additional sanity checks to determine whether the response
is suitable for time synchronization purposes.
```go
err := response.Validate()
if err == nil {
    // response data is suitable for synchronization purposes
}
```

If you wish to customize the behavior of the NTP query, use the
[`QueryWithOptions`](https://godoc.org/github.com/beevik/ntp#QueryWithOptions)
function:
```go
options := ntp.QueryOptions{ Timeout: 30*time.Second, TTL: 5 }
response, err := ntp.QueryWithOptions("0.beevik-ntp.pool.ntp.org", options)
time := time.Now().Add(response.ClockOffset)
```

Configurable [`QueryOptions`](https://godoc.org/github.com/beevik/ntp#QueryOptions)
include:
* `Timeout`: How long to wait before giving up on a response from the NTP
  server.
* `Version`: Which version of the NTP protocol to use (2, 3 or 4).
* `TTL`: The maximum number of IP hops before the request packet is discarded.
* `LocalAddress`: The local IP address to use when sending the query. Useful
  when the host has multiple network interfaces.
* `Auth`: The symmetric authentication key and algorithm used by the server to
  authenticate the query. The same information is used by the client to
  authenticate the server's response.
* `Extensions`: Extensions may be added to modify NTP queries before they are
	transmitted and to process NTP responses after they arrive.
* `GetSystemTime`: A custom function to obtain the current system time, used
  to override the platform's default system clock API call.
* `Dialer`: A custom network connection "dialer" function used to override the
  default UDP dialer function.


## Logging responses

To log an NTP query's response, use the response's `Log` function:
```go
options := ntp.QueryOptions{ Version: 4, RequestSupportedVersions: true }
response, err := ntp.QueryWithOptions("0.beevik-ntp.pool.ntp.org", options)
if err != nil {
    response.Log(os.Stdout)
}
```

Output:
```
    Version: 4
ClockOffset: -374.811087ms
        RTT: 67.989037ms
 SystemTime: Sun Sep 20 2026  18:36:41.96194660 (PDT)
  ~TrueTime: Sun Sep 20 2026  18:36:41.58713551 (PDT)
 ClientXmit: Mon Sep 21 2026  01:36:41.89013280 (UTC)
 ServerRecv: Mon Sep 21 2026  01:36:41.54931623 (UTC)
 ServerXmit: Mon Sep 21 2026  01:36:41.54937899 (UTC)
 ClientRecv: Mon Sep 21 2026  01:36:41.95818460 (UTC)
    Stratum: 3
       Leap: No Warning
      Flags: [Synchronized] (0x00000001)
        Era: 0
  Timescale: UTC
       Poll: 1s
  Precision: 29ns
  RootDelay: 20.111084ms
   RootDisp: 366.211µs
   RootDist: 44.416271ms
  Supported: [4]
   MinError: 340.816569ms
    RefTime: Mon Sep 21 2026  01:35:21.44779491 (UTC)
      RefID: 158.51.99.19 (0x9e336313)
   KissCode: <empty>
```

## Experimental NTPv5 support

This package supports the [current draft of NTP version 5
(NTPv5)](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-ntpv5). The
implementation provided by this package is considered experimental and is
subject to change as the draft specification evolves. For this reason, this
package's NTPv5 features are not recommended for use in production
environments.


## Using the NTP pool

The NTP pool is a shared resource provided by the [NTP Pool
Project](https://www.pool.ntp.org/en/) and used by people and services all
over the world. To prevent it from becoming overloaded, please avoid querying
the standard `pool.ntp.org` zone names in your applications. Instead, consider
requesting your own [vendor zone](http://www.pool.ntp.org/en/vendors.html) or
[joining the pool](http://www.pool.ntp.org/join.html).


## Network Time Security (NTS)

Network Time Security (NTS) is a recent enhancement of NTP, designed to add
better authentication and message integrity to the protocol. It is defined by
[RFC 8915](https://tools.ietf.org/html/rfc8915). If you wish to use NTS, see
the [nts package](https://github.com/beevik/nts). (The nts package is
implemented as an extension to this package.)
