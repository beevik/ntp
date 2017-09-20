[![Build Status](https://travis-ci.org/beevik/ntp.svg?branch=master)](https://travis-ci.org/beevik/ntp)
[![GoDoc](https://godoc.org/github.com/beevik/ntp?status.svg)](https://godoc.org/github.com/beevik/ntp)

ntp
===

The ntp package is an implementation of a simple NTP client. It allows you
to connect to a remote NTP server and request the current time.

To request the current time, simply do the following:
```go
time, err := ntp.Time("0.beevik-ntp.pool.ntp.org")
```

To request the current time along with additional metadata, use the Query
function:
```go
response, err := ntp.Query("0.beevik-ntp.pool.ntp.org")
```

To use the NTP pool in your application, please request your own
[vendor zone](http://www.pool.ntp.org/en/vendors.html).  Avoid using 
the `[number].pool.ntp.org` zone names in your applications.
