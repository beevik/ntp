ntp
===

The ntp package is a small implementation of a limited NTP client. It
requests the current time from a remote NTP server according to
selected version of the NTP protocol. Client uses version 4 of the NTP protocol
RFC 5905 by default.

Use `ntp.Version` variable to specify NTP protocol version. Available values are
`ntp.V2`, `ntp.V3` and `ntp.V4`

The approach was inspired by a post to the go-nuts mailing list by
Michael Hofmann:

https://groups.google.com/forum/?fromgroups#!topic/golang-nuts/FlcdMU5fkLQ
