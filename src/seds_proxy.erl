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
-module(seds_proxy).
-behaviour(gen_fsm).

-include_lib("kernel/src/inet_dns.hrl").
-include("seds.hrl").

-record(state, {
        ip,
        port,
        dnsfd,          % dns server socket
        s,              % proxied socket

        sum_up = 0,     % number of bytes sent to server
        sum_down = 0,   % number of bytes received from server
        buf = [],       % last packet sent (for resend)
        data = [<<>>]   % list of binaries: data returned by proxied server
    }).

-define(MAXBUFSZ, 1024 * 1024 * 1024).  % 1 Mb

% Interface
-export([send/7]).
-export([start_link/3]).
% States
-export([connect/2,proxy/2]).
% Behaviours
-export([init/1, handle_event/3, handle_sync_event/4,
        handle_info/3, terminate/3, code_change/4]).


%%--------------------------------------------------------------------
%%% Interface
%%--------------------------------------------------------------------
send(Pid, IP, Port, #dns_rec{} = Query, up, Sum, Data) when is_pid(Pid) ->
    gen_fsm:send_event(Pid, {up, IP, Port, Query, Sum, Data});
send(Pid, IP, Port, #dns_rec{} = Query, down, Sum, _) when is_pid(Pid) ->
    gen_fsm:send_event(Pid, {down, IP, Port, Query, Sum}).

%%--------------------------------------------------------------------
%%% Behaviours
%%--------------------------------------------------------------------
start_link(Socket, ServerIP, ServerPort) ->
    {ok, Pid} = gen_fsm:start(?MODULE, [
            Socket,
            ServerIP,
            ServerPort
        ], []),
    erlang:monitor(process, Pid),
    {ok, Pid}.

init([DNSSocket, ServerIP, ServerPort]) ->
    process_flag(trap_exit, true),
    {ok, connect, #state{
            dnsfd = DNSSocket,
            ip = ServerIP,
            port = ServerPort
        }, 0}.


handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {next_state, StateName, State}.


%%
%% State: proxy
%%

% From server
handle_info({tcp, Socket, Data}, proxy, #state{s = Socket, data = Buf} = State) ->
    N = iolist_size(Buf),
    if 
        N < ?MAXBUFSZ ->
            {next_state, proxy, State#state{data = [Data|Buf]}, ?PROXY_TIMEOUT};
        N < ?MAXBUFSZ*3 ->
            error_logger:info_report([{buffer_disabled, N}]),
            ok = inet:setopts(Socket, [{active, false}]),
            {next_state, proxy, State#state{data = [Data|Buf]}, ?PROXY_TIMEOUT};
        true ->
            {stop, enobufs, State}
    end;

% Connection closed
handle_info({tcp_closed, Socket}, proxy, #state{s = Socket} = State) ->
    {stop, shutdown, State}.

terminate(Reason, StateName, #state{
        ip = IP,
        port = Port,
        sum_up = Up,
        sum_down = Down
    }) ->
    error_logger:info_report([
            {session_end, {IP, Port}},
            {bytes_sent, Up},
            {bytes_rcvd, Down},
            {state, StateName},
            {reason, Reason}
        ]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.


%%--------------------------------------------------------------------
%%% States
%%--------------------------------------------------------------------

%%
%% connect
%%
connect(timeout, #state{ip = IP, port = Port} = State) ->
    {ok, Socket} = gen_tcp:connect(IP, Port, [
            binary,
            {packet, 0},
            {active, true}
        ], 5000),
    {next_state, proxy, State#state{s = Socket}}.


%%
%% proxy
%%

% client sent data to be forwarded to server
proxy({up, IP, Port, Rec, ClientSum, Data},
    #state{
        sum_up = Sum,
        dnsfd = DNSSocket,
        s = Socket
    } = State) ->

    Payload = base32:decode(string:to_upper(Data)),
    Sum1 = Sum + length(Payload),

    case response(up, ClientSum, Rec, State) of
        error ->
            {stop, {up, out_of_sync}, State};
        {duplicate, Packet} ->
            error_logger:info_report([{dropping, {IP, Port}}]),
            ok = gen_udp:send(DNSSocket, IP, Port, Packet),
            {next_state, proxy, State, ?PROXY_TIMEOUT};
        Packet ->
            ok = gen_tcp:send(Socket, Payload),
            ok = gen_udp:send(DNSSocket, IP, Port, Packet),
            {next_state, proxy, State#state{sum_up = Sum1},
                ?PROXY_TIMEOUT}
    end;

% client requested pending data from server
proxy({down, IP, Port,
        #dns_rec{
            qdlist = [#dns_query{
                    type = Type
                }|_]} = Rec, ClientSum},
        #state{
            sum_down = Sum,
            dnsfd = DNSSocket,
            s = Socket,
            data = Data
        } = State) ->

    {Payload, Size, Rest} = seds_protocol:data(Type, Data),

    case response({down, Payload}, ClientSum, Rec, State) of
        error ->
            {stop, {down, out_of_sync}, State};
        {duplicate, Packet} ->
            error_logger:info_report([{resending, {IP, Port, Sum}}]),
            ok = gen_udp:send(DNSSocket, IP, Port, Packet),
            {next_state, proxy, State, ?PROXY_TIMEOUT};
        Packet ->
            ok = inet:setopts(Socket, [{active, true}]),
            ok = gen_udp:send(DNSSocket, IP, Port, Packet),
            {next_state, proxy, State#state{
                sum_down = Sum + Size,
                data = [Rest],
                buf = Data}, ?PROXY_TIMEOUT}
    end;

proxy(timeout, State) ->
    {stop, timeout, State}.

%%--------------------------------------------------------------------
%%% Internal Functions
%%--------------------------------------------------------------------
seq(N) when is_integer(N) ->
    <<I1,I2,I3,I4>> = <<N:32>>,
    {I1,I2,I3,I4}.

%% Packet sum checks
response(up, Sum, Rec, #state{sum_up = Sum}) ->
    seds_protocol:encode(seq(Sum), Rec);
response({down, Payload}, Sum, Rec, #state{sum_down = Sum}) ->
    seds_protocol:encode(Payload, Rec);
response(up, Sum1, Rec, #state{sum_up = Sum2}) when Sum1 < Sum2 ->
    {duplicate, seds_protocol:encode(seq(Sum2), Rec)};
response({down, _}, Sum1, 
    #dns_rec{qdlist = [#dns_query{type = Type}|_]} = Rec,
    #state{sum_down = Sum2, buf = Data}) when Sum1 < Sum2 ->
    {Payload, _, _} = seds_protocol:data(Type, Data),
    {duplicate, seds_protocol:encode(Payload, Rec)};
response(_, _, _, _) ->
    error.
