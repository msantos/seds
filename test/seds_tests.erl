%%% Copyright (c) 2015, Michael Santos <michael.santos@gmail.com>
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
-module(seds_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/src/inet_dns.hrl").
-include_lib("seds/include/seds.hrl").

decode_test() ->
    Domains = [
        % Data request for dynamically forwarded address with port
        {"0-1234.id-98765.d.127.0.0.1-2222.x.sshdns.example.com",
            #seds{
                dir = down,
                id = 98765,
                forward = {forward,{{127,0,0,1},2222}},
                sum = 0,
                domain = ["sshdns","example","com"],
                data = []
            }
        },

        % Data request for dynamically forwarded address with port
        {"0-1234.id-98765.d.127.0.0.1.x.sshdns.example.com",
            #seds{
                dir = down,
                id = 98765,
                forward = {forward,{{127,0,0,1},22}},
                sum = 0,
                domain = ["sshdns","example","com"],
                data = []
            }
        },

        % Data request for static port
        {"0-1234.id-98765.down.sshdns.example.com",
            #seds{
                dir = down,
                id = 33229,
                forward = {session,1},
                sum = 0,
                domain = ["sshdns","example","com"],
                data = []
            }
        }
    ],
    [ begin Rec = #dns_rec{
                    header = #dns_header{
                        qr = false,
                        opcode = 'query'
                    },
                    qdlist = [
                        #dns_query{
                            domain = Domain,
                            type = txt,
                            class = in
                        }
                    ]
                },
                Result = seds_protocol:decode(Rec)
        end || {Domain, Result} <- Domains ],
    ok.

data_test() ->
    Small = binary:copy(<<"x">>, 60),
    Large = binary:copy(<<"x">>, 256),
    Data = [
        {{txt, Small},
            {["eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"], 60,<<>>}},
        {{txt, Large},
         {["eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
           "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg="],
           220,<<"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">>}},

        {{null, Small},
         {<<"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4">>,
            60,<<>>}},
        {{null, Large},
         {<<"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==">>,
            220,<<"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">>}},

        {{cname, Small},
         {"PB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6D.YPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DY",
                60,<<>>}},
        {{cname, Large},
         {"PB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6D.YPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6.DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DYPB4HQ6DY",
            110, <<"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">>}}
    ],
    [ Result = seds_protocol:data(Type, Bin) || {{Type,Bin}, Result} <- Data ],
    ok.

bad_ipv4_test() ->
    Domain = "0-1234.id-98765.d.127.257.0.1-2222.x.sshdns.example.com",
    Rec = #dns_rec{
        header = #dns_header{
            qr = false,
            opcode = 'query'
        },
        qdlist = [
            #dns_query{
                domain = Domain,
                type = txt,
                class = in
            }
        ]
    },
    ?assertException(
        exit,
        badarg,
        seds_protocol:decode(Rec)
    ).

bad_port_test() ->
    Domain = "0-1234.id-98765.d.127.225.0.1-123456.x.sshdns.example.com",
    Rec = #dns_rec{
        header = #dns_header{
            qr = false,
            opcode = 'query'
        },
        qdlist = [
            #dns_query{
                domain = Domain,
                type = txt,
                class = in
            }
        ]
    },
    ?assertException(
        exit,
        badarg,
        seds_protocol:decode(Rec)
    ).
