seds
====

seds is the server side for tunnelling TCP sockets over the DNS
protocol. seds is written in Erlang.

A client (and a small, standalone server written in C) is available here:

    https://github.com/msantos/sods

Quick Start
-----------

    ## setup configuration
    cp rel/sys.config.dist rel/sys.config
    vi rel/sys.config

    ## build and run for development
    $ rebar3 do compile, ct, release

    # run the server
    $ ./_build/default/rel/seds/bin/seds foreground

Installing a Release
--------------------

    ## build a production release
    $ rebar3 as prod tar

    # install as root to /usr/local/lib/seds

    $ mkdir -p /usr/local/lib/seds
    $ cd /usr/local/lib/seds
    $ tar zxvf /path/to/seds-0.3.0.tar.gz

    # restrict procket executable
    # chown root:<group> lib/procket-*/priv/procket
    $ chmod u+s lib/procket-*/priv/procket

    # run the server
    $ /usr/local/lib/seds/bin/seds start

Using Low Ports
---------------

`seds` uses procket to listen on port 53. For instructions on setting
up the procket setuid helper, see:

    https://github.com/msantos/procket

Using ports above 1023 does not require any additional configuration.

Configuration
-------------

The seds configuration uses Erlang terms. Options are:

    ip:
        type: inet:ip_address()
        default: any
        description:
            Binds service to this IP address

    port:
        type: inet:port_number()
        default: 53
        description:
            Port bound by service. Using a port below 1024 requires
            setting up the procket setuid helper.

    forward:
        type: [{inet:ip_address(), inet:port_number()}]
        default: []
        description:
            List of destination IP addresses/port. The forwarded session
            can be selected by number (the list of sessions is numbered
            from 0).

    dynamic:
        type: true | false
        default: false
        description:
            Enables client specified session forwarding. The destination
            ports can be controlled using the 'allowed_ports' and
            'acl' options.

    domains:
        type: [string()]
        default: []
        description:
            Whitelist of accepted domain names. Queries for domains not
            included in this list will be ignored.

    allowed_ports:
        type: [inet:port_number()]
        default: [22]
        description:
            Whitelist of ports allowed when the dynamic option (client
            specified forwarding) is enabled.

    acl:
        type: [[char()]]
        default: []
        description:
            Blacklisted network classes. Can be used, for example,
            to disallow dynamic session forwarding to localhost.

            For example, to disallow IPv4 private networks and the
            broadcast address:

~~~ erlang
{acl, [
        [10],
        [127],
        [172,16],
        [192,168],
        [255,255,255,255]
      ]}
~~~

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

