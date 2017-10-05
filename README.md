[![Build Status](https://travis-ci.org/beevik/ntp.svg?branch=master)](https://travis-ci.org/beevik/ntp)
[![GoDoc](https://godoc.org/github.com/beevik/ntp?status.svg)](https://godoc.org/github.com/beevik/ntp)

ntp
===

The ntp package is an implementation of a Simple NTP (SNTP) client based on
[RFC5905](https://tools.ietf.org/html/rfc5905). It allows you to connect to
a remote NTP server and request the current time.

If all you care about is the current time according to a remote NTP server,
simply use the `Time` function:
```go
time, err := ntp.Time("0.beevik-ntp.pool.ntp.org")
```

To obtain the current time as well as some additional metadata about the time,
use the `Query` function instead:
```go
response, err := ntp.Query("0.beevik-ntp.pool.ntp.org")
```

If you want to override the default behavior of the `Query` function, you
can do so with the `QueryWithOptions` function:
```go
options := ntp.QueryOptions{ Timeout: 30*time.Second, TTL: 5 }
response, err := ntp.QueryWithOptions("0.beevik-ntp.pool.ntp.org", options)
```

To validate a `Query` response in order to determine whether it's suitable
for synchronization purposes, use the `Validate` method:
```go
err := response.Validate()
if err == nil {
    // response data is suitable for synchronization purposes
}
```

The `Response` structure returned by the `Query` functions contains useful
metadata about the time query, including:
* `Time`: The time the server transmitted its response, according to its own clock.
* `ClockOffset`: The estimated offset of the local system clock relative to the server's clock. You may apply this offset to any system clock reading once the query is complete.
* `RTT`: An estimate of the round-trip-time delay between the client and the server.
* `Precision`: The precision of the server's clock reading.
* `Stratum`: The stratum level of the server, which indicates the number of hops from the server to the reference clock.
* `ReferenceID`: A unique identifier for the consulted reference clock.
* `ReferenceTime`: The time at which the server last updated its local clock setting.
* `RootDelay`: The server's aggregate round-trip-time delay to the stratum 1 server.
* `RootDispersion`: The server's estimated maximum measurement error relative to the reference clock.
* `RootDistance`: An estimate of the root synchronization distance between the client and the stratum 1 server.
* `Leap`: The leap second indicator, indicating whether a second should be added to or removed from the current month's last minute.
* `MinError`: A lower bound on the clock error between the client and the server.
* `Poll`: The maximum polling interval between successive messages to the server.

To use the NTP pool in your application, please request your own
[vendor zone](http://www.pool.ntp.org/en/vendors.html).  Avoid using 
the `[number].pool.ntp.org` zone names in your applications.
