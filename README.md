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

The **topic specification** is an MQTT wildcard match: `+` matches everything except `/` and `#` matches everything including `/`.
Caveat: "subscribe" ACL requests are also MQTT wildcard matches, there may be corner cases with unexpected behaviour.

