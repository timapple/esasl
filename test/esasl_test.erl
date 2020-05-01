%%%-------------------------------------------------------------------
%%% File    : esasl_test.erl
%%% Author  : Mikael Magnusson <mikael@skinner.hem.za.org>
%%% Description : SASL authentication library
%%%
%%% Created : 23 May 2007 by Mikael Magnusson <mikael@skinner.hem.za.org>
%%%-------------------------------------------------------------------
%%%
%%% Copyright (C) 2007  Mikael Magnusson <mikma@users.sourceforge.net>
%%%
%%% Permission is hereby granted, free of charge, to any person
%%% obtaining a copy of this software and associated documentation
%%% files (the "Software"), to deal in the Software without
%%% restriction, including without limitation the rights to use, copy,
%%% modify, merge, publish, distribute, sublicense, and/or sell copies
%%% of the Software, and to permit persons to whom the Software is
%%% furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be
%%% included in all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
%%% EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
%%% MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
%%% NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
%%% BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
%%% ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
%%% CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
%%% SOFTWARE.
%%%

-module(esasl_test).

%%====================================================================
%% Test functions
%%====================================================================

test() ->
    test(["xmpp", gethostname(), "xmpp.keytab"]).

gethostname() ->
    {ok, Name} = inet:gethostname(),
    case inet:gethostbyname(Name) of
	{ok, Hostent} when is_record(Hostent, hostent) ->
	    Hostent#hostent.h_name;
	_ ->
	    Name
    end.

test([Service, Hostname, Key_tab]) when is_list(Service),
					is_list(Hostname),
					is_list(Key_tab) ->
    process_flag(trap_exit, true),
    {ok, Pid} = start_link(Key_tab, ""),
    Test = proc_lib:start_link(?MODULE, test_init, [Pid, Service, Hostname]),
    Result =
	receive
	    {'EXIT', Test, Reason} ->
		error_logger:info_msg("Result ~p ~p~n", [Test, Reason]),
		Reason;
	    E ->
		error_logger:info_msg("Error ~p~n", [E])
	end,
    process_flag(trap_exit, false),
    io:format("test success~n",[]),
    stop(Pid),
    Result.

test_init(Pid, Service, Host_name) ->
    process_flag(trap_exit, true),
    Server = proc_lib:start_link(?MODULE, server_init, [Pid, Service, Host_name]),
    Client = proc_lib:start_link(?MODULE, client_init, [Pid, Service, Host_name]),

    Server ! {set_peer, Client},
    Client ! {set_peer, Server},
    Client ! {data, <<>>},

    proc_lib:init_ack(self()),
    test_loop(Server, Client),
    ok.

test_loop(exit, exit) ->
    error_logger:info_msg("Test exit~n", []),
    ok;
test_loop(Server, Client) ->
    error_logger:info_msg("test_loop ~p ~p~n", [Server, Client]),

    receive
	{'EXIT', Server, Reason} ->
	    error_logger:info_msg("Server exit ~p~n", [Reason]),
	    exit(Reason);
	{'EXIT', Client, Reason} ->
	    error_logger:info_msg("Client exit ~p~n", [Reason]),
	    test_loop(Server, exit);
	S ->
	    io:format("message ~p~n", [S]),
	    test_loop(Server, Client)
    end.

client_init(Pid, Service, Host_name) ->
    error_logger:info_msg("client_init ~p ~p~n", [self(), Pid]),

    {ok, Client} = client_start(Pid, "GSSAPI", Service, Host_name),
    error_logger:info_msg("client_init ~p ~p~n", [self(), Client]),
    property_set(Client, authid, "authid_foo"),
    property_set(Client, authzid, "authzid_foo"),
    property_set(Client, password, "secret"),
    proc_lib:init_ack(self()),
    sasl_loop(Client, client, undefined_client).

server_init(Pid, Service, Host_name) ->
    error_logger:info_msg("server_init ~p ~p~n", [self(), Pid]),

    {ok, Server} = server_start(Pid, "GSSAPI", Service, Host_name),
    error_logger:info_msg("server_init ~p ~p~n", [self(), Server]),
    proc_lib:init_ack(self()),
    sasl_loop(Server, server, undefined_server).

sasl_loop(Ref, Mode, Peer) ->
    receive
	{data, Data} ->
	    error_logger:info_msg("data received~n", []),
	    sasl_data(Ref, Mode, Peer, Data),
	    sasl_loop(Ref, Mode, Peer);
	{set_peer, Peer1} ->
	    error_logger:info_msg("set_peer received~n", []),
	    sasl_loop(Ref, Mode, Peer1);
	stop ->
	    exit(normal)
    end.

sasl_data(Ref, Mode, Peer, Data) ->
    case step(Ref, Data) of
	{needsmore, Resp} ->
	    Peer ! {data, Resp};
	{ok, Resp} ->
	    if Resp == "" ->
		    ignore;
	       true ->
		    Peer ! {data, Resp}
	    end,
	    if Mode == server ->
		    Authid = property_get(Ref, authid),
		    Authzid = property_get(Ref, authzid),
		    Display_name = property_get(Ref, gssapi_display_name),
		    error_logger:info_msg("authid:~p authzid:~p display:~p~n", [Authid, Authzid, Display_name]),
		    finish(Ref),
		    exit({authenticated, Authzid, Display_name});
	       Mode == client ->
		    exit(normal)
	    end;
	{error, Reason} ->
	    exit({error, Reason})
    end.
