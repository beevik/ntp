Release v1.4.1
==============

**Updates**

* Upgraded package dependencies to retrieve security fixes.

Release v1.4.0
==============

**Changes**

* Added a protocol `Version` field to the `Response` struct.

Release v1.3.1
==============

**Changes**

* Added AES-256-CMAC support for symmetric authentication.
* Symmetric auth keys may now be specified as ASCII or HEX using the "ASCII:"
  or "HEX:" prefixes.
* Updated dependencies to address security issues.

**Fixes**

* Added proper handling of the empty string when used as a server address.

Release v1.3.0
==============

**Changes**

* Added the `ReferenceString` function to `Response`. This generates a
  stratum-specific string for the `ReferenceID` value.
* Optimized the AES CMAC calculation for 64-bit architectures.

**Fixes**

* Fixed a bug introduced in release v1.2.0 that was causing IPv6 addresses
  to be interpreted incorrectly.

Release v1.2.0
==============

**Changes**

* Added support for NTP extensions by exposing an extension interface.
  Extensions are able to (1) modify NTP messages before being sent to
  the server, and (2) process NTP messages after they arrive from the
  server. This feature has been added in preparation for NTS support.
* Added support for RFC 5905 symmetric key authentication.
* Allowed server address to be specified as a "host:port" pair.
* Brought package into further compliance with IETF draft on client data
  minimization.
* Declared error variables as part of the public API.
* Added a `Dialer` field to `QueryOptions`. This replaces the deprecated
  `Dial` field.
* Added an `IsKissOfDeath` function to the `Response` type.

**Deprecated**

* Deprecated the `Port` field in QueryOptions.
* Deprecated the `Dial` field in QueryOptions.

Release v1.1.1
==============

**Fixes**

* Fixed a missing indirect go module dependency.

Release v1.1.0
==============

**Changes**

* Added the `Dial` property to the `QueryOptions` struct. This allows the user
  to override the default UDP dialer when setting up a connection to a remote
  NTP server.

Release v1.0.0
==============

This package has been stable for several years with no bug reports in that
time. It is also pretty much feature complete. I am therefore updating the
version to 1.0.0.

Because this is a major release, all previously deprecated code has been
removed from the package.

**Breaking changes**

* Removed the `TimeV` function. Use `Time` or `QueryWithOptions` instead.

Release v0.3.2
==============

**Changes**

* Rename unit tests to enable easier test filtering.

Release v0.3.0
==============

There have been no breaking changes or further deprecations since the
previous release.

**Changes**

* Fixed a bug in the calculation of NTP timestamps.

Release v0.2.0
==============

There are no breaking changes or further deprecations in this release.

**Changes**

* Added `KissCode` to the `Response` structure.


Release v0.1.1
==============

**Breaking changes**

* Removed the `MaxStratum` constant.

**Deprecations**

* Officially deprecated the `TimeV` function.

**Internal changes**

* Removed `minDispersion` from the `RootDistance` calculation, since the value
  was arbitrary.
* Moved some validation into main code path so that invalid `TransmitTime` and
  `mode` responses trigger an error even when `Response.Validate` is not
  called.


Release v0.1.0
==============

This is the initial release of the `ntp` package.  Currently it supports the
following features:
* `Time()` to query the current time according to a remote NTP server.
* `Query()` to query multiple pieces of time-related information from a remote
  NTP server.
* `QueryWithOptions()`, which is like `Query()` but with the ability to
  override default query options.

Time-related information returned by the `Query` functions includes:
* `Time`: the time the server transmitted its response, according to the
  server's clock.
* `ClockOffset`: the estimated offset of the client's clock relative to the
  server's clock. You may apply this offset to any local system clock reading
  once the query is complete.
* `RTT`: an estimate of the round-trip-time delay between the client and the
  server.
* `Precision`: the precision of the server's clock reading.
* `Stratum`: the "stratum" level of the server, where 1 indicates a server
  directly connected to a reference clock, and values greater than 1
  indicating the number of hops from the reference clock.
* `ReferenceID`: A unique identifier for the NTP server that was contacted.
* `ReferenceTime`: The time at which the server last updated its local clock
  setting.
* `RootDelay`: The server's round-trip delay to the reference clock.
* `RootDispersion`: The server's total dispersion to the referenced clock.
* `RootDistance`: An estimate of the root synchronization distance.
* `Leap`: The leap second indicator.
* `MinError`: A lower bound on the clock error between the client and the
  server.
* `Poll`: the maximum polling interval between successive messages on the
   server.

The `Response` structure returned by the `Query` functions also contains a
`Response.Validate()` function that returns an error if any of the fields
returned by the server are invalid.
