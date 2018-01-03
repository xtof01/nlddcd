nlddcd - Netlink-based Dynamic DNS Client Daemon
================================================

**nlddcd** is a Dynamic DNS client. It monitors network interfaces for
address changes. When a change is detected for an interface specified in
the configuration file, the new address is sent to the Dynamic DNS service
configured for that interface, using an HTTP or HTTPS request.

**nlddcd** does not rely on periodic requests to an external service in
order to detect address changes, but uses the Netlink interface to be
notified of changes. Consequently, **nlddcd** does not work behind a NAT
and must instead run directly on the router that contains the interface
carrying the "external" IP address(es).

**nlddcd** supports IPv4 and IPv6 addresses and will automatically send
updates containing both address types of a configured interface
(however, only global, non-temporary IPv6 addresses will be considered).
