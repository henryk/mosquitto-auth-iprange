# mosquitto-auth-iprange

License: GPL-3

Implements IP address range checks (both IPv4 and IPv6) for Mosquitto MQTT authentication.

## Quick Start

````bash
make install
````

Then edit `/etc/mosquitto/mosquitto.conf` (or, depending on configuration system, create a file in `/etc/mosquitto/conf.d`) and put in something like this:

````
auth_plugin /usr/local/lib/mosquitto-auth-iprange.so

auth_opt_iprange allow ::1 #
auth_opt_iprange allow 127.0.0.1 #
````

## Status

 + ACL checks are fully functional.
 + Username/pw checks are not implemented yet.
 + A preliminary pattern match method to match IP addresses against topics is implemented. This should be replaced with something more expressive.
 + MQTT Pattern matching for subscription checks is not implemented correctly.

## ACL Rules

Each `auth_opt_iprange` specifies an ACL rule, consisting of a *verdict*, an *address specification*, and a *topic specification*. The rules are evaluated in the order that they appear in the configuration file, and later matching rules override earlier matches. There are three different types of access that can be allowed or denied (or ignored): *reading* on a topic (that is: receiving a message that was posted), *writing* to a topic (posting a message), and *subscribing* to a topic (which is distinct from, but necessary for, reading).
When the ACL rule evaluation ends in "ignore" (the default), the plugin does not give a result for this ACL request, allowing other plugins in the broker to be queried. (If no plugin gives an "allow" result the request is denied by default.)

The **verdict** may be:

 + `allow`: Allow read, write, subscribe
 + `deny`: Deny read, write, subscribe
 + `ignore`: Ignore read, write, subscribe
 + A *mode string* of the form `[+|-|~][r][w][s]`
    + `+`: The following modes are allowed, this is the default if no modifier is specified
    + `-`: The following modes are denied
    + `~`: The following modes are ignored
    + `r`: Read
    + `w`: Write
    + `s`: Subscribe

Composite mode strings of the form `+r-w` are allowed.

The **address specification** has the form `ip_or_host[/prefix_length]`. Hostnames are resolved at startup (or configuration reload time) and rules for every result are added. The prefix length is optional (defaults to the full address size of 32 for IPv4 or 128 for IPv6) and specifies a prefix/subnet match.

The **topic specification** is an MQTT wildcard match: `+` matches everything except `/`, and `#` matches everything including `/`.

Caveat: "subscribe" ACL requests are also MQTT wildcard matches, and the libmosquitto `mosquitto_topic_matches_sub` method fails when matching wildcards against wildcards. As a workaround, verbatim matches work: allowing `#` for subscription means that a client requesting `#` on subscription is allowed, but a client requesting a subscription `#/foo` would not be allowed under that rule, even though it should be.

Special case: **IP pattern match**. When the topic is of the form `% foo_%1$02x` it will be interpreted as a `printf(3)` format string with POSIX numbered parameter extensions. Internally, `printf` is called with the given format string with each byte of the IP address as an argument. In all cases, 16 arguments are given. For IPv4 the first four contain the IPv4 address bytes (in big-endian order), for IPv6 all 16 address bytes are provided as arguments. The result of the format string expansion is passed to the normal MQTT wildcard match mechanism.

Examples:

````
auth_opt_iprange allow 10.0.0.0/8 % devices/%1$d.%2$d.%3$d.%4$d/#
auth_opt_iprange allow fe80::/10 % status/%15$d02X%16$d02X
````

will allow the following accesses:

 + Host `10.1.2.3` to `devices/10.1.2.3/#`
 + Host `fe80::1234:5678:abcd:ef01` to `status/EF01`

