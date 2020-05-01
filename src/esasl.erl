%%%-------------------------------------------------------------------
%%% File    : gsasl.erl
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

%%%
%%% TODO: link gsasl process in server_start/client_start and unlink in stop
%%%

-module(esasl).

%% API
-export([start_link/0,
	 start_link/1,
	 start_link/2,
	 start_link/3,
	 stop/1,
	 server_start/4,
	 client_start/4,
	 finish/1,
	 step/2,
	 property_get/2,
	 str_error/2,
	 property_set/3,
	 mechlist/2]).

%% Internal exports
-export([init/4]).

-include_lib("kernel/include/inet.hrl").

-define(APP, esasl).

%%====================================================================
%% API
%%====================================================================

%%--------------------------------------------------------------------
%% Function: start_link([Server_name], [KeyTab, Ccname])
%%           Server_name = {local, Name}
%%           Name = atom()
%%           KeyTab = string(), path to Kerberos keytab
%%           Ccname = string(), Kerberos credential cache name
%% Descrip.: Start gsasl port driver 
%% Returns : {ok, Pid}
%%           Pid = pid()
%%--------------------------------------------------------------------
start_link() ->
    start_link("", "").
start_link(Server_name) ->
    start_link(Server_name, "", "").
start_link(KeyTab, Ccname) when is_list(KeyTab), is_list(Ccname) ->
    start_link('$anonymous', KeyTab, Ccname).
start_link(Server_name, KeyTab, Ccname) when is_list(KeyTab), is_list(Ccname) ->
    ExtProg = filename:join(code:priv_dir(?APP), "gsasl_drv"),
    {ok, proc_lib:start_link(?MODULE, init,
			     [Server_name, KeyTab, ExtProg, Ccname])}.

%%--------------------------------------------------------------------
%% Function: stop(Server_ref)
%%           Server_ref = Name | pid()
%%           Name = atom(), registered name
%% Descrip.: Stop gsasl port driver
%% Returns : ok
%%           
%%--------------------------------------------------------------------
stop(Server_ref) ->
    Server_ref ! stop,
    ok.

%%--------------------------------------------------------------------
%% Function: server_start(Server_ref, Mech, Service, Host)
%%           Server_ref = Name | pid()
%%           Mech = string(), SASL mechanism
%%           Name = atom(), registered name
%%           Service = string(), SASL service name (ex. "HTTP").
%%           Host = string(), server FQDN 
%% Descrip.: Initiate server SASL authentication instance
%% Returns : {ok, Instance} | {error, no_mem}
%%           Instance = integer(), opaque index referencing the instance
%%--------------------------------------------------------------------
server_start(Server_ref, Mech, Service, Host) when is_list(Mech),
						   is_list(Service),
						   is_list(Host) ->
    Pid = lookup_server(Server_ref),
    case call_port(Pid, {start, {server, Mech, Service, Host}}) of
	{ok, Ref} ->
	    {ok, {Pid, Ref}};
	E ->
	    E
    end;
server_start(Server_ref, Mech, Service, Host) when is_list(Mech),
						   is_list(Service),
						   is_binary(Host) ->
    server_start(Server_ref, Mech, Service, binary_to_list(Host)).

%%--------------------------------------------------------------------
%% Function: client_start(Server_ref, Mech, Service, Host)
%%           Server_ref = Name | pid()
%%           Mech = string(), SASL mechanism
%%           Name = atom(), registered name
%%           Service = string(), SASL service name (ex. "HTTP").
%%           Host = string(), server FQDN 
%% Descrip.: Initiate client SASL authentication instance
%% Returns : {ok, Instance} | {error, no_mem}
%%           Instance = integer(), opaque index referencing the instance
%%--------------------------------------------------------------------
client_start(Server_ref, Mech, Service, Host) when is_list(Mech),
						   is_list(Service),
						   is_list(Host) ->
    Pid = lookup_server(Server_ref),
    case call_port(Pid, {start, {client, Mech, Service, Host}}) of
	{ok, Ref} ->
	    {ok, {Pid, Ref}};
	E ->
	    E
    end.

%%--------------------------------------------------------------------
%% Function: step(Instance, Input)
%%           Instance = integer(), SASL instance
%%           Input = binary(), SASL input data
%% Descrip.: Perform one step of SASL authentication
%% Returns : {ok, Output} |
%%           {needsmore, Output} |
%%           {error, bad_instance} |
%%           {error, authentication_error}
%%           Output = binary(), SASL output data
%%--------------------------------------------------------------------
step({Pid, Instance}, Input) when is_pid(Pid),
				  is_integer(Instance),
				  is_binary(Input) ->
    call_port(Pid, {step, {Instance, Input}}).

%%--------------------------------------------------------------------
%% Function: property_get(Instance, Name)
%%           Instance = integer(), SASL instance
%%           Name = string(), Property name, one of "authid", "authzid"
%%               and "gssapi_display_name"
%% Descrip.: Get a SASL property
%% Returns : {ok, Value} |
%%           {error, bad_instance} |
%%           {error, bad_property}
%%           {error, not_found}
%%           Value = string(), SASL property value
%%--------------------------------------------------------------------
property_get({Pid, Instance}, Name) when is_pid(Pid),
					 is_integer(Instance),
					 is_atom(Name) ->
    call_port(Pid, {property_get, {Instance, Name}}).

str_error({Pid, _Instance}, Err) when is_pid(Pid),
				      is_integer(Err) ->
    call_port(Pid, {str_error, Err});
str_error(Server_ref, Err) when is_integer(Err) ->
    call_port(Server_ref, {str_error, Err}).

%%--------------------------------------------------------------------
%% Function: property_set(Instance, Name, Value)
%%           Instance = integer(), SASL instance
%%           Name = string(), Property name, one of "authid", "authzid"
%%               and "gssapi_display_name"
%%           Value = string(), SASL property value
%% Descrip.: Set a SASL property
%% Returns : {ok, set} |
%%           {error, bad_instance} |
%%           {error, bad_property}
%%--------------------------------------------------------------------
property_set({Pid, Instance}, Name, Value) when is_pid(Pid),
						is_integer(Instance),
						is_atom(Name), is_list(Value) ->
    call_port(Pid, {property_set, {Instance, Name, Value}}).

%%--------------------------------------------------------------------
%% Function: finish(Instance)
%%           Instance = integer(), SASL instance
%% Descrip.: Release SASL instance
%% Returns : {ok, finished} |
%%           {error, bad_instance}
%%--------------------------------------------------------------------
finish({Pid, Instance}) when is_pid(Pid),
			     is_integer(Instance) ->
    call_port(Pid, {finish, Instance}).

mechlist(Server_ref, Mode) ->
    case call_port(Server_ref, {mechlist, Mode}) of
	{ok, List} ->
	    {ok, string:tokens(List, " ")};
	E ->
	    E
    end.

%% Internal functions

lookup_server(Server_ref) ->
    if
	is_pid(Server_ref) -> Server_ref;
	is_atom(Server_ref) -> whereis(Server_ref)
    end.

call_port(Pid, Msg) ->
    error_logger:info_msg("call_port ~p~n", [Msg]),
    Ref = make_ref(),
    Pid ! {gsasl_call, {self(), Ref}, Msg},
    receive
	{gsasl_reply, _Pid, Ref, Result} ->
	    error_logger:info_msg("call_port Result ~p~n", [Result]),
	    Result
    end.

init(ServerName, KeyTab, ExtPrg, Ccname) ->
    case ServerName of
	'$anonymous' ->
	    ignore;
	{local, Name} ->
	    register(Name, self())
    end,
	    
    process_flag(trap_exit, true),
    KeyTabEnv =
	if KeyTab =/= [] ->
		[{"KRB5_KTNAME", KeyTab}];
	   true ->
		[]
	end,
    Ccname_env =
	if Ccname =/= [] ->
		[{"KRB5CCNAME", Ccname}];
	   true ->
		[]
	end,
    Env = KeyTabEnv ++ Ccname_env,
    error_logger:info_msg("port env ~p~n", [Env]),
    Port = open_port({spawn, ExtPrg}, [{packet, 2}, binary, exit_status, {env,  Env}]),
    error_logger:info_msg("port inited~n", []),
    proc_lib:init_ack(self()),
    loop(Port, []).

loop(Port, Queue) ->
    receive
	{gsasl_call, {Caller, From}, Msg} ->
	    error_logger:info_msg("~p: Calling port with ~p: ~p~n", [self(), Caller, Msg]),
%% 	    case Msg of
%% 		{start, _Arg} ->
%% 		    Res = link(Caller),
%% 		    error_logger:info_msg("link ~p~n", [Res])
%% 	    end,

	    erlang:port_command(Port, term_to_binary(Msg)),
	    Queue1 = Queue ++ [{Caller, Msg, From}],
	    loop(Port, Queue1);

	{Port, {data, Data}} ->
	    Term = binary_to_term(Data),
	    [{Caller, _Msg, From} | Queue1] = Queue,
	    error_logger:info_msg("~p: Result ~p: ~p~n", [self(), Caller, Term]),
	    Caller ! {gsasl_reply, self(), From, Term},
	    loop(Port, Queue1);
	{Port, {exit_status, Status}} when Status > 128 ->
	    error_logger:error_msg("Port terminated with signal: ~p~n", [Status-128]),
	    exit({port_terminated, Status});
	{Port, {exit_status, Status}} ->
	    error_logger:error_msg("Port terminated with status: ~p~n", [Status]),
	    exit({port_terminated, Status});
	{'EXIT', Port, Reason} ->
	    exit(Reason);
	stop ->
	    erlang:port_close(Port),
	    exit(normal);
	Term ->
	    error_logger:error_msg("Unhandled term ~p~n", [Term])
	    loop(Port, Queue)
    end.
