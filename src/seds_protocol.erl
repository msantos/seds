%% Copyright (c) 2010-2015, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(seds_protocol).

-include_lib("kernel/src/inet_dns.hrl").
-include("seds.hrl").

-export([decode/1]).

%%%
%%% Handle decoding of the data embedded in the different
%%% record types.
%%%
decode(Query) when is_binary(Query) ->
    {ok, Rec} = inet_dns:decode(Query),
    decode(Rec);
decode(#dns_rec{
            header = #dns_header{
                qr = false,
                opcode = 'query'
            },
            qdlist = [#dns_query{
                    domain = Query,
                    type = Type,
                    class = in
                }|_]
        }) ->
    {Prefix, Session} = lists:split(string:chr(Query, $-), Query),
    type(Type, [Prefix|string:tokens(Session, ".-")]).

% mfz.wiztb.onsgmcq.40966-0.id-372571.u.192.168.100.101-2222.x.example.com
% B64._Nonce-Sum.id-SessionId.u.IP1.IP2.IP3.IP4-Port.x.Domain
type(a, [Base64Nonce, Sum, "id", SessionId,
        "u", IP1, IP2, IP3, IP4, Port, "x"|Domain]) ->
    IP = makeaddr({IP1,IP2,IP3,IP4}),
    Port1 = list_to_integer(Port),
    B64 = string:tokens(Base64Nonce, "."),
    Forward = forward({IP, Port1}),
    #seds{
        dir = up,
        forward = Forward,
        id = SessionId,
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };
type(a, [Base64Nonce, Sum, "id", SessionId,
        "u", IP1, IP2, IP3, IP4, "x"|Domain]) ->
    IP = makeaddr({IP1,IP2,IP3,IP4}),
    B64 = string:tokens(Base64Nonce, "."),
    Forward = forward({IP, 22}),
    #seds{
        dir = up,
        forward = Forward,
        id = SessionId,
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };

% mfz.wiztb.onsgmcq.40966-0.id-372571.up.p.example.com
% B64._Nonce-Sum.id-SessionId.up.Domain
type(a, [Base64Nonce, Sum, "id", SessionId, "up"|Domain]) ->
    B64 = string:tokens(Base64Nonce, "."),
    {Forward, Id} = forward(list_to_integer(SessionId)),
    #seds{
        dir = up,
        forward = Forward,
        id = Id,
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };

% 0-29941.id-10498.d.192.168.100.101.s.p.example.com
% Sum-Nonce.id-SessionId.d.IP1.IP2.IP3.IP4.Domain
%
% 0-29941.id-10498.d.192.168.100.101-2222.x.p.example.com
% Sum-Nonce.id-SessionId.d.IP1.IP2.IP3.IP4-Port.x.Domain
type(_Type, [Sum, _Nonce, "id", SessionId,
        "d", IP1, IP2, IP3, IP4, Port, "x"|Domain]) ->
    IP = makeaddr({IP1,IP2,IP3,IP4}),
    Port1 = list_to_integer(Port),
    Forward = forward({IP, Port1}),
    #seds{
        dir = down,
        forward = Forward,
        id = SessionId,
        sum = list_to_sum(Sum),
        domain = Domain
    };
type(_Type, [Sum, _Nonce, "id", SessionId,
        "d", IP1, IP2, IP3, IP4, "x"|Domain]) ->
    IP = makeaddr({IP1,IP2,IP3,IP4}),
    Forward = forward({IP, 22}),
    #seds{
        dir = down,
        forward = Forward,
        id = SessionId,
        sum = list_to_sum(Sum),
        domain = Domain
    };

% 0-29941.id-10498.down.s.p.example.com
% Sum-Nonce.id-SessionId.down.Domain
type(_Type, [Sum, _Nonce, "id", SessionId, "down"|Domain]) ->
    {Forward, Id} = forward(list_to_integer(SessionId)),
    #seds{
        dir = down,
        forward = Forward,
        id = Id,
        sum = list_to_sum(Sum),
        domain = Domain
    }.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
makeaddr({IP1,IP2,IP3,IP4}) when is_list(IP1), is_list(IP2), is_list(IP3), is_list(IP4) ->
    {list_to_integer(IP1), list_to_integer(IP2), list_to_integer(IP3), list_to_integer(IP4)}.

% Remove the trailing dash and convert to an integer
list_to_sum(N) when is_list(N) ->
    list_to_integer(string:strip(N, right, $-)).

forward({_IP, _Port} = Forward) ->
    {forward, Forward};
forward(Id) when is_integer(Id) ->
    <<_Opt:8, Forward:8, SessionId:16>> = <<Id:32>>,
    {{session, Forward}, SessionId}.
