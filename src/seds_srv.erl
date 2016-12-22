%% Copyright (c) 2010-2016, Michael Santos <michael.santos@gmail.com>
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
-module(seds_srv).
-behaviour(gen_server).

-compile([{parse_transform, lager_transform}]).

-include_lib("kernel/src/inet_dns.hrl").
-include("seds.hrl").

-define(SERVER, ?MODULE).

-export([start_link/0]).
-export([send/4]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).

-record(state, {
        acf = false :: boolean(),                       % allow client forwarding
        acl = [] :: [[byte()]],                         % forward IP blacklist
        acl_port = [inet:port_number()],                % allowed ports (whitelist)

        f = [] :: [{inet:ip_address(),inet:port_number()}],  % forwarders map
        s :: port(),                                    % socket port
        fd :: integer(),                                % socket fd
        d = [] :: [string()],                           % domains
        p = dict:new()                                  % list of proxies
    }).


-spec send(inet:ip_address(), inet:port_number(), #dns_rec{}, #seds{}) -> ok.
send(IP, Port, #dns_rec{} = Rec, #seds{} = Query) ->
    gen_server:call(?SERVER, {send, IP, Port, Rec, Query}).

-spec start_link() -> 'ignore' | {'error',_} | {'ok',pid()}.
start_link() ->
    IP = application:get_env(seds, ip, any),
    Port = application:get_env(seds, port, 53),
    gen_server:start_link({local, ?SERVER}, ?MODULE, [IP,Port], []).

-spec init([inet:ip_address() | inet:port_number()]) -> {'ok',#state{}}.
init([IP, Port]) when Port > 1024 ->
    init(IP, Port, []);
init([IP, Port]) ->
    Options = [{protocol, udp}, {family, inet}, {type, dgram}] ++ case IP of
        any -> [];
        IP -> [{ip, IP}]
    end,

    {ok, FD} = procket:open(Port, Options),

    init(any, 0, [{fd, FD}]).

-spec init(any | inet:ip_address(),inet:port_number(),proplists:proplist()) ->
    {'ok',#state{}}.
init(IP, Port, Opt) ->
    process_flag(trap_exit, true),

    Options = [binary, {active,once}] ++ case IP of
        any -> [];
        IP -> [{ip, IP}]
    end ++ Opt,

    {ok, Socket} = gen_udp:open(Port, Options),

    {ok, #state{
            acf = application:get_env(seds, dynamic, false),
            acl = application:get_env(seds, acl, []),
            acl_port = application:get_env(seds, allowed_ports, [22]),
            f = application:get_env(seds, forward, []),
            d = [ string:tokens(N, ".") ||
                N <- application:get_env(seds, domains, ["localhost"]) ],
            s = Socket,
            fd = proplists:get_value(fd, Opt, undefined)
        }}.

handle_call({send, IP, Port, Rec, #seds{
            dir = Dir,
            sum = Sum,
            data = Data
        } = Query}, _From, #state{p = Proxies} = State) ->
    Session = session(Query, State),
    case dict:find(Session, Proxies) of
        error when Sum == 0 ->
            P = try
                {ok, Proxy} = proxy(Session, State),
                ok = seds_proxy:send(Proxy, IP, Port, Rec, Dir, 0, Data),
                dict:store(Session, Proxy, Proxies)
            catch
                _:_ ->
                    Proxies
            end,
            {reply, ok, State#state{p = P}};
        error ->
            {reply, ok, State};
        {ok, Proxy} ->
            try
                ok = seds_proxy:send(Proxy, IP, Port, Rec, Dir, Sum, Data)
            catch
                _:_ -> ok
            end,
            {reply, ok, State}
    end;

handle_call(Request, _From, State) ->
    lager:error("unhandled call: ~p", [Request]),
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

% DNS request from client
handle_info({udp, Socket, IP, Port, Data}, #state{
        s = Socket
    } = State) ->
    ok = inet:setopts(Socket, [{active, once}]),
    spawn(fun() -> decode(IP, Port, Data, State) end),
    {noreply, State};

% Session terminated
handle_info({'DOWN', _Ref, process, Pid, _Reason}, #state{
        p = Proxies
    } = State) ->
    {noreply, State#state{
            p = dict:filter(
                fun (_,V) when V == Pid -> false;
                    (_,_) -> true
                end,
                Proxies)
        }};

% WTF?
handle_info(Info, State) ->
    lager:error("unhandled info", [Info]),
    {noreply, State}.

terminate(_Reason, #state{s = Socket, fd = FD}) ->
    gen_udp:close(Socket),
    procket:close(FD),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%%
%%% Internal Functions
%%%

%%--------------------------------------------------------------------
%%% Sessions: which IP:Port to send the data
%%--------------------------------------------------------------------

% Static list of forwarded hosts:port, identified from offset 0
-spec session(#seds{},#state{}) ->
    {{inet:ip_address(),inet:port_number()},non_neg_integer()}.
session(#seds{
        forward = {session, Forward},
        id = Id
    }, #state{f = Map}) ->
    F = case Forward + 1 of
        N when N > length(Map) -> 1;
        N when N < 1 -> 1;
        N -> N
    end,
    {lists:nth(F, Map), Id};
% Dynamic forwarding requested by client
session(#seds{
        forward = {forward, Forward},
        id = Id
    }, _State) ->
    {Forward, Id}.

% Decode the data embedded in the DNS record.
%
% The decode function is spawned as an unlinked process. If the
% parsing succeeds, the data is returned to the gen_server. If
% the process crashes, the query is dropped.
%
-spec decode(inet:ip_address(),inet:port_number(),binary(),#state{}) -> 'ok'.
decode(IP, Port, Data, State) ->
    {ok, Query} = inet_dns:decode(Data),
    Decoded = seds_protocol:decode(Query),
    true = allow(Decoded, State),
    seds_srv:send(IP, Port, Query, Decoded).

-spec proxy({{inet:ip_address(),inet:port_number()},non_neg_integer()},
    #state{}) -> {'ok',pid()}.
proxy({{IP, Port}, Id}, #state{
        s = Socket
    }) ->
    lager:info("New connection dst ~s port ~p id:~p", [
        inet_parse:ntoa(IP),
        Port,
        Id
    ]),
    seds_proxy:start_link(Socket, IP, Port).

-spec allow(#seds{},#state{}) -> boolean().
allow(#seds{
        forward = {forward, {IP, Port}},
        domain = Domain
    }, #state{
        d = Domains,
        acf = true,
        acl = ACL,
        acl_port = ACP
    }) ->
    check_dn(Domain, Domains) and
    check_acl(IP, ACL) and
    check_port(Port, ACP);
allow(#seds{
        domain = Domain
    }, #state{
        d = Domains
    }) ->
    check_dn(Domain, Domains).

% Respond only to the configured list of domains
-spec check_dn(string(),[string()]) -> boolean().
check_dn(Domain, Domains) ->
    [ N || N <- Domains, lists:suffix(N, Domain) ] /= [].

-spec check_acl({byte(),byte(),byte(),byte()},[[byte()]]) -> boolean().
check_acl({IP1,IP2,IP3,IP4}, ACL) ->
    [ N || N <- ACL, lists:prefix(N, [IP1,IP2,IP3,IP4]) ] == [].

-spec check_port(inet:port_number(),[inet:port_number()]) -> boolean().
check_port(Port, Allowed) ->
    lists:member(Port, Allowed).
