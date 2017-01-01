seds
====

seds is the server side for tunnelling TCP sockets over the DNS
protocol. seds is written in Erlang.

A client (and a small, standalone server written in C) is available here:

    https://github.com/msantos/sods

Quick Start
-----------

    # setup configuration
    cp rel/sys.config.dist rel/sys.config
    vi rel/sys.config

    $ rebar3 do compile, release

    # run the server
    $ ./_build/default/rel/seds/bin/seds foreground

Using Low Ports
---------------

_seds_ uses procket to listen on port 53. See:

    https://github.com/msantos/procket

Using ports abouve 1024 does not require any additional configuration.

Configuration
-------------

The seds configuration uses Erlang terms. Options are:

    ip:
        type: inet:ip_address()
        description: binds service to this IP address

    port:
        type: inet:port_number()
        description: port for service

    forward:
        type: [{inet:ip_address(), inet:port_number()}]
        description:
            List of destination IP addresses/port. The forwarded session
            can be selected by number (sessions begin with 0).

    dynamic:
        type: true | false
        description:
            Enables client specified session forwarding. The destination
            ports can be controlled using the 'allowed_ports' and
            'acl' option.

    domains:
        type: [string()]
        description:
            Whitelist of accepted domain names. Queries for domains not
            on this list will be ignored.

    allowed_ports:
        type: [inet:port_number()]
        description:
            Whitelist of ports allowed when dynamic sessions is enabled.

    acl:
        type: [[char()]]
        description:
            Blacklisted network classes. Can be used, for example,
            to disallow dynamic session forwarding to localhost.

Example
-------

~~~ erlang
[{seds, [
    {port, 53},
    {dynamic, true},
    {acl, []},
    {allowed_ports, [22, 443]},
    {forward, []},
    {domains, ["example.com", "example2.com"]}
    ]}].
~~~

