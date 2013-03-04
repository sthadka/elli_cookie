%%%-------------------------------------------------------------------
%%% @author aj heller <aj@drfloob.com>
%%% @copyright (C) 2012, aj heller
%%% @doc A library application for reading and managing cookies in elli.
%%% @end
%%% Created :  3 Oct 2012 by aj heller <aj@drfloob.com>
%%%-------------------------------------------------------------------
-module(elli_cookie).

%% Basic Cookie Management
-export([parse/1,
         get/2, get/3,
         new/1, new/2, new/3,
         delete/1, delete/2]).

%% Cookie Options
-export([expires/1, path/1, domain/1, secure/0, http_only/0, max_age/1]).

-include_lib("elli/include/elli.hrl").

-type cookie() :: {binary(), binary()}.
-type cookie_list() :: [cookie()].
-type cookie_option() :: {atom(), string()}.


%% returns a proplist made from the submitted cookies
-spec parse(Req :: #req{}) -> no_cookies | cookie_list().
parse(Req = #req{}) ->
    tokenize(elli_request:get_header(<<"Cookie">>, Req)).


%% gets a specific cookie value from the set of parsed cookie
-spec get(Key :: binary(), Cookies :: cookie_list()) -> undefined | binary().
get(_, no_cookies) ->
    undefined;
get(Key, Cookies) ->
    true = valid_cookie_name(Key),
    proplists:get_value(Key, Cookies).

-spec get(Key :: binary(), Cookies :: cookie_list(), Default) -> Default | binary().
get(_, no_cookies, Default) ->
    Default;
get(Key, Cookies, Default) ->
    true = valid_cookie_name(Key),
    proplists:get_value(Key, Cookies, Default).

%% creates multiple new cookies
-spec new([{Name :: binary(), Value :: binary()} |
           {Name :: binary(), Value :: binary(), Options ::
            [cookie_option()]}]) -> cookie().
new(PList) ->
    lists:map(fun ({Name, Value}) ->
                      new(Name, Value);
                  ({Name, Value, Options}) ->
                      new(Name, Value, Options)
              end, PList).

%% creates a new cookie in a format appropriate for server response
-spec new(Name :: binary(), Value :: binary()) -> cookie().
new(Name, Value) ->
    true = valid_cookie_name(Name),
    true = valid_cookie_value(Value),
    BName = Name,
    BVal = Value,
    {<<"Set-Cookie">>, <<BName/binary, "=", BVal/binary>>}.

-spec new(Name :: binary(), Value :: binary(), Options :: [cookie_option()]) -> cookie().
new(Name, Value, Options) ->
    true = valid_cookie_name(Name),
    true = valid_cookie_value(Value),
    BName = Name,
    BValue = Value,
    Bin = <<BName/binary,"=",BValue/binary>>,
    FinalBin = lists:foldl(fun set_cookie_attribute/2, Bin, Options),
    {<<"Set-Cookie">>, FinalBin}.

%% Creates a header that will delete a specific cookie on the client
-spec delete(Name :: binary()) -> cookie().
delete(Name) ->
    delete(Name, []).

-spec delete(Name :: binary(), Options :: [cookie_option()]) -> cookie().
delete(Name, Options) ->
    true = valid_cookie_name(Name),
    new(Name, <<>>, [expires({{1970,1,1},{0,0,0}}) | Options]).



%%------------------------------------------------------------
%% Cookie Option helpers
%%------------------------------------------------------------

%% set a path for a cookie
path(P) ->
    {path, P}.
%% set a domain for a cookie
domain(P) ->
    {domain, P}.
%% make the cookie secure (SSL)
secure() ->
    secure.
%% make an http-only cookie
http_only() ->
    http_only.




%% set cookie expiration
expires({S, seconds}) ->
    expires_plus(S);
expires({M, minutes}) ->
    expires_plus(M*60);
expires({H, hours}) ->
    expires_plus(H*60*60);
expires({D, days}) ->
    expires_plus(D*24*60*60);
expires({W, weeks}) ->
    expires_plus(W*7*24*60*60);
expires(Date) ->
    {expires, to_bin(httpd_util:rfc1123_date(Date))}.



max_age({S, seconds}) ->
    {max_age, to_bin(S)};
max_age({M, minutes}) ->
    {max_age, to_bin(M*60)};
max_age({H, hours}) ->
    {max_age, to_bin(H*60*60)};
max_age({D, days}) ->
    {max_age, to_bin(D*24*60*60)};
max_age({W, weeks}) ->
    {max_age, to_bin(W*7*24*60*60)};
max_age(Seconds) ->
    {max_age, to_bin(Seconds)}.


%%------------------------------------------------------------
%% Internal
%%------------------------------------------------------------

to_bin(B) when is_binary(B) ->
        B;
to_bin(L) when is_list(L) ->
        list_to_binary(L);
to_bin(I) when is_integer(I) ->
    list_to_binary(integer_to_list(I));
to_bin(X) ->
        throw({error, {not_a_string, X}}).

tokenize(<<>>) ->
    [];
tokenize(CookieStr) when is_binary(CookieStr) ->
    Cookies = binary:split(CookieStr, <<";">>, [trim, global]),
    lists:map(fun tokenize2/1, Cookies);
tokenize(_) ->
    no_cookies.

tokenize2(NVP) ->
    case binary:split(NVP, <<"=">>, [trim]) of
        [N, V] -> {trimre(N), trimre(V)};
        [N]    -> {trimre(N), <<>>}
    end.

% From
% https://groups.google.com/forum/?fromgroups=#!topic/erlang-programming/gSvv6ARI21U
trimre(Bin) ->
        re:replace(Bin, "^\\s+|\\s+$", "", [{return, binary}, global]).

set_cookie_attribute({expires, Exp}, Bin) ->
    <<Bin/binary, ";Expires=", Exp/binary>>;
set_cookie_attribute({max_age, Exp}, Bin) ->
    <<Bin/binary, ";Max-Age=", Exp/binary>>;
set_cookie_attribute({path, Path}, Bin) ->
    <<Bin/binary, ";Path=", Path/binary>>;
set_cookie_attribute({domain, Domain}, Bin) ->
    <<Bin/binary, ";Domain=", Domain/binary>>;
set_cookie_attribute(secure, Bin) ->
    <<Bin/binary, ";Secure">>;
set_cookie_attribute(http_only, Bin) ->
    <<Bin/binary, ";HttpOnly">>;
set_cookie_attribute(X, _) ->
    throw({error, {invalid_cookie_attribute, X}}).



expires_plus(N) ->
    UT = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    UTE = UT + N,
    Date = calendar:gregorian_seconds_to_datetime(UTE),
    {expires, to_bin(httpd_util:rfc1123_date(Date))}.




%%------------------------------------------------------------
%% Predicates
%%------------------------------------------------------------


%% TODO: implement cookie spec checking: https://tools.ietf.org/html/rfc6265
valid_cookie_name(B) when is_binary(B) ->
    (binary:match(B, <<"=">>) == nomatch) orelse
        {invalid_cookie_name, B};
valid_cookie_name(X) ->
    {invalid_cookie_name, X}.


%% TODO: implement cookie spec checking: https://tools.ietf.org/html/rfc6265
valid_cookie_value(B) when is_binary(B) ->
    true;
valid_cookie_value(X) ->
    {invalid_cookie_value, X}.
