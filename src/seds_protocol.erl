%% Copyright (c) 2010-2017, Michael Santos <michael.santos@gmail.com>
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

-compile([{parse_transform, lager_transform}]).

-include_lib("kernel/src/inet_dns.hrl").
-include("seds.hrl").

-export([decode/1]).
-export([encode/2, data/2, seq/1]).

-define(MAXDATA, 110).

%%--------------------------------------------------------------------
%%% Decode
%%--------------------------------------------------------------------

%%%
%%% Handle decoding of the data embedded in the different
%%% record types.
%%%
-spec decode(binary() | seds:dns_rec()) -> seds:seds().
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
    decode_type(Type, [Prefix|string:tokens(Session, ".-")]).

% mfz.wiztb.onsgmcq.40966-0.id-372571.u.192.168.100.101-2222.x.example.com
% B64._Nonce-Sum.id-SessionId.u.IP1.IP2.IP3.IP4-Port.x.Domain
-spec decode_type(atom(), [string(), ...]) -> seds:seds().
decode_type(a, [Base64Nonce, Sum, "id", SessionId,
        "u", IP1, IP2, IP3, IP4, Port, "x"|Domain]) ->
    IP = makeaddr({IP1, IP2, IP3, IP4}),
    Port1 = string_to_port_number(Port),
    B64 = string:tokens(Base64Nonce, "."),
    Forward = forward({IP, Port1}),
    #seds{
        dir = up,
        forward = Forward,
        id = list_to_integer(SessionId),
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };
decode_type(a, [Base64Nonce, Sum, "id", SessionId,
        "u", IP1, IP2, IP3, IP4, "x"|Domain]) ->
    IP = makeaddr({IP1, IP2, IP3, IP4}),
    B64 = string:tokens(Base64Nonce, "."),
    Forward = forward({IP, 22}),
    #seds{
        dir = up,
        forward = Forward,
        id = list_to_integer(SessionId),
        data = lists:flatten(lists:sublist(B64, length(B64)-1)),
        sum = list_to_integer(Sum),
        domain = Domain
    };

% mfz.wiztb.onsgmcq.40966-0.id-372571.up.p.example.com
% B64._Nonce-Sum.id-SessionId.up.Domain
decode_type(a, [Base64Nonce, Sum, "id", SessionId, "up"|Domain]) ->
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
decode_type(_Type, [Sum, _Nonce, "id", SessionId,
        "d", IP1, IP2, IP3, IP4, Port, "x"|Domain]) ->
    IP = makeaddr({IP1, IP2, IP3, IP4}),
    Port1 = string_to_port_number(Port),
    Forward = forward({IP, Port1}),
    #seds{
        dir = down,
        forward = Forward,
        id = list_to_integer(SessionId),
        sum = list_to_sum(Sum),
        domain = Domain
    };
decode_type(_Type, [Sum, _Nonce, "id", SessionId,
        "d", IP1, IP2, IP3, IP4, "x"|Domain]) ->
    IP = makeaddr({IP1, IP2, IP3, IP4}),
    Forward = forward({IP, 22}),
    #seds{
        dir = down,
        forward = Forward,
        id = list_to_integer(SessionId),
        sum = list_to_sum(Sum),
        domain = Domain
    };

% 0-29941.id-10498.down.s.p.example.com
% Sum-Nonce.id-SessionId.down.Domain
decode_type(_Type, [Sum, _Nonce, "id", SessionId, "down"|Domain]) ->
    {Forward, Id} = forward(list_to_integer(SessionId)),
    #seds{
        dir = down,
        forward = Forward,
        id = Id,
        sum = list_to_sum(Sum),
        domain = Domain
    }.


%%--------------------------------------------------------------------
%%% Encode
%%--------------------------------------------------------------------

%% Encode the data returned by the server as a DNS record
-spec data(atom(), binary()) ->
    {iodata(), non_neg_integer(), binary()}.
data(_, <<>>) ->
    {[], 0, <<>>};

% TXT records
data(txt, <<D1:?MAXDATA/bytes, D2:?MAXDATA/bytes, Rest/binary>>) ->
    {[base64:encode_to_string(D1), base64:encode_to_string(D2)],
     2*?MAXDATA, Rest};
data(txt, <<D1:?MAXDATA/bytes, Rest/binary>>) ->
    {[base64:encode_to_string(D1)], ?MAXDATA, Rest};
data(txt, Data) ->
    {[base64:encode_to_string(Data)], byte_size(Data), <<>>};

% NULL records
data(null, <<D1:(?MAXDATA*2)/bytes, Rest/binary>>) ->
    {base64:encode(D1), ?MAXDATA*2, Rest};
data(null, Data) ->
    {base64:encode(Data), byte_size(Data), <<>>};

% CNAME records
data(cname, <<D1:?MAXDATA/bytes, Rest/binary>>) ->
    {label(base32:encode(D1)), ?MAXDATA, Rest};
data(cname, Data) ->
    {label(base32:encode(Data)), byte_size(Data), <<>>}.

% The sequence number is encoded as an IPv4 address in the DNS reply.
-spec seq(integer()) -> {byte(), byte(), byte(), byte()}.
seq(N) when is_integer(N) ->
    <<I1, I2, I3, I4>> = <<N:32>>,
    {I1, I2, I3, I4}.

%% Encode the DNS response to the client
-spec encode(iodata() | {byte(), byte(), byte(), byte()}, seds:dns_rec())
    -> binary().
encode(Data, #dns_rec{
        header = Header,
        qdlist = [#dns_query{
                domain = Domain,
                type = Type
            }|_]} = Rec) ->
    inet_dns:encode(Rec#dns_rec{
            header = Header#dns_header{
                qr = true,
                ra = true
            },
            anlist = [#dns_rr{
                    domain = Domain,
                    type = Type,
                    data = Data
                }]}).

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
-spec string_to_byte(string()) -> byte().
string_to_byte(N) ->
    string_to_int(N, 1 bsl 8).

-spec string_to_port_number(string()) -> inet:port_number().
string_to_port_number(N) ->
    string_to_int(N, 1 bsl 16).

string_to_int(N, Max) ->
    case list_to_integer(N) of
        X when X < Max -> X;
        _ -> exit(badarg)
    end.

%%
%% decode
%%
-spec makeaddr({string(), string(), string(), string()}) ->
    {byte(), byte(), byte(), byte()}.
makeaddr({IP1, IP2, IP3, IP4})
  when is_list(IP1), is_list(IP2), is_list(IP3), is_list(IP4)
       -> {string_to_byte(IP1),
           string_to_byte(IP2),
           string_to_byte(IP3),
           string_to_byte(IP4)}.

% Remove the trailing dash and convert to an integer
-spec list_to_sum(string()) -> integer().
list_to_sum(N) when is_list(N) ->
    list_to_integer(string:strip(N, right, $-)).

-spec forward(non_neg_integer() | {inet:ip_address(), inet:port_number()}) ->
    {'forward' | {'session', byte()},
        char() | {inet:ip_address(), inet:port_number()}}.
forward({_IP, _Port} = Forward) ->
    {forward, Forward};
forward(Id) when is_integer(Id) ->
    <<_Opt:8, Forward:8, SessionId:16>> = <<Id:32>>,
    {{session, Forward}, SessionId}.

%%
%% encode
%%
%% Each component (or label) of a CNAME can have a
%% max length of 63 bytes. A "." divides the labels.
-spec label(string()) -> string().
label(String) when length(String) < ?MAXLABEL ->
    String;
label(String) ->
    re:replace(String, lists:concat([".{", ?MAXLABEL, "}"]), "&.",
        [global, {return, list}]).
