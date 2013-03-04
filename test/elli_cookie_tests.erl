-module(elli_cookie_tests).

-include_lib("elli/include/elli.hrl").
-include_lib("eunit/include/eunit.hrl").

parse_test() ->
    ?assertError(function_clause, elli_cookie:parse(#req{}))
     , ?assertEqual([{<<"1">>, <<>>}], elli_cookie:parse(#req{headers=[{<<"Cookie">>, <<"1=">>}]}))
     , ?assertEqual([{<<"1">>, <<>>}, {<<"2">>, <<"3">>}],
                     elli_cookie:parse(#req{headers=[{<<"Cookie">>, <<"1= ;2=3;">>}]}))
     , ?assertEqual([{<<"1">>, <<>>}, {<<"2">>, <<"3">>}],
                     elli_cookie:parse(#req{headers=[{<<"Cookie">>, <<"1=;2=3;">>}]}))

    , ?assertEqual(no_cookies, elli_cookie:parse(#req{headers=[]}))
    , ?assertEqual([{<<"1">>, <<"2">>}], elli_cookie:parse(#req{headers=[{<<"Cookie">>, <<"1=2">>}]}))
    , ?assertEqual([{<<"1">>, <<"2">>}, {<<"3">>, <<"4">>}], elli_cookie:parse(#req{headers=[{<<"Cookie">>, <<"1=2; 3=4">>}]}))
    , ?assertEqual([{<<"1">>, <<"2">>}, {<<"3">>, <<"4">>}, {<<"five">>, <<"six">>}]
		    , elli_cookie:parse(#req{headers=[{<<"Cookie">>, <<"1=2; 3=4; five   =    six">>}]})).

get_test() ->
    Cookies = [{<<"1">>, <<"two">>}, {<<"three">>, <<"4">>}],
    ?assertEqual(undefined, elli_cookie:get(<<"nope">>, []))
     , ?assertEqual(undefined, elli_cookie:get(<<"nope">>, Cookies))
     , ?assertEqual(<<"two">>, elli_cookie:get(<<"1">>, Cookies))
     , ?assertEqual(<<"4">>, elli_cookie:get(<<"three">>, Cookies))
     , ?assertEqual(undefined, elli_cookie:get(<<"4">>, Cookies))
     , ?assertEqual(nope, elli_cookie:get(<<"4">>, Cookies, nope))
     , ?assertError({badmatch, {invalid_cookie_name, <<"4=">>}},
                     elli_cookie:get(<<"4=">>, Cookies, nope)).


get_noCookies_test() ->
    ?assertEqual(undefined, elli_cookie:get("x", no_cookies))
     , ?assertEqual(undefined, elli_cookie:get("x", no_cookies, undefined))
     , ?assertEqual(bort, elli_cookie:get("x", no_cookies, bort)).


new_test() ->
     ?assertMatch({<<"Set-Cookie">>, <<"name=val">>}, elli_cookie:new(<<"name">>, <<"val">>))
     , ?assertMatch({<<"Set-Cookie">>, <<"name=val">>}, elli_cookie:new(<<"name">>, <<"val">>))
     , ?assertError({badmatch, {invalid_cookie_value, bork}}, elli_cookie:new(<<"name">>, bork))
     , ?assertError({badmatch, {invalid_cookie_name, bork}}, elli_cookie:new(bork, "val"))
     , ?assertMatch({<<"Set-Cookie">>, <<"name=val=">>}, elli_cookie:new(<<"name">>, <<"val=">>))
     , ?assertMatch({<<"Set-Cookie">>, <<"name=val=">>}, elli_cookie:new(<<"name">>, <<"val=">>))
     , ?assertError({badmatch, {invalid_cookie_name, <<"name=">>}}, elli_cookie:new(<<"name=">>, <<"val">>))

     %% multiple cookies
     , ?assertMatch([{<<"Set-Cookie">>, <<"k1=v1">>}, {<<"Set-Cookie">>, <<"k2=v2">>}],
                     elli_cookie:new([{<<"k1">>, <<"v1">>}, {<<"k2">>, <<"v2">>}]))

     %% be careful: binaries are not checked for stringyness
     , ?assertMatch({_, <<1, "=val">>}, elli_cookie:new(<<1>>, <<"val">>))

     , ?assertThrow({error, {invalid_cookie_attribute, domain}}, elli_cookie:new(<<"n">>, <<"v">>, [domain, "/"]))
     , ?assertMatch({_, <<"n=v;Domain=www.example.com">>},
                     elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:domain(<<"www.example.com">>)]))
     , ?assertMatch({_, <<"n=v;Path=/">>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:path(<<"/">>)]))
     , ?assertMatch({_, <<"n=v;Secure">>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:secure()]))
     , ?assertMatch({_, <<"n=v;HttpOnly">>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:http_only()]))

     %% elli_cookie:expires tests
     , ?assertMatch({_, <<"n=v;Expires=", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:expires({2,seconds})]))
     , ?assertMatch({_, <<"n=v;Expires=", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:expires({2,minutes})]))
     , ?assertMatch({_, <<"n=v;Expires=", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:expires({2,hours})]))
     , ?assertMatch({_, <<"n=v;Expires=", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:expires({2,days})]))
     , ?assertMatch({_, <<"n=v;Expires=", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:expires({2,weeks})]))

     %% elli_cookie:max_age tests
     , ?assertMatch({_, <<"n=v;Max-Age=2", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:max_age({2,seconds})]))
     , ?assertMatch({_, <<"n=v;Max-Age=120", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:max_age({2,minutes})]))
     , ?assertMatch({_, <<"n=v;Max-Age=7200", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:max_age({2,hours})]))
     , ?assertMatch({_, <<"n=v;Max-Age=172800", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:max_age({2,days})]))
     , ?assertMatch({_, <<"n=v;Max-Age=1209600", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:max_age({2,weeks})]))
     , ?assertMatch({_, <<"n=v;Max-Age=69", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:max_age(69)]))

     , ?assertMatch({_, <<"n=v;Expires=", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:expires(calendar:local_time())]))
     , ?assertMatch({_, <<"n=v;Expires=Fri, 21 Mar 2014", _/binary>>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:expires({{2014,03,21},{16,20,42}})]))

     %% be careful: cookie options are not thoroughly sanity checked.
     , ?assertMatch({_, <<"n=v;Domain=/">>}, elli_cookie:new(<<"n">>, <<"v">>, [elli_cookie:domain(<<"/">>)])).


delete_test() ->
     ?assertError({badmatch, {invalid_cookie_name, bork}}, elli_cookie:delete(bork))
     , ?assertError({badmatch, {invalid_cookie_name, 1}}, elli_cookie:delete(1))
     , ?assertError({badmatch, {invalid_cookie_name, <<"=">>}}, elli_cookie:delete(<<"=">>))

     , ?assertEqual({<<"Set-Cookie">>, <<"test=;Expires=Wed, 31 Dec 1969 23:00:00 GMT">>}, elli_cookie:delete(<<"test">>))
     , ?assertMatch({_, <<"test=;Expires=Wed, 31 Dec 1969 23:00:00 GMT", _/binary>>}, elli_cookie:delete(<<"test">>))
     , ?assertError({badmatch, {invalid_cookie_name, <<"=">>}}, elli_cookie:delete(<<"=">>))

     %% with Options
     , ?assertError({badmatch, {invalid_cookie_name, bork}}, elli_cookie:delete(bork, [elli_cookie:domain(<<"/">>)]))
     , ?assertError({badmatch, {invalid_cookie_name, 1}}, elli_cookie:delete(1, [elli_cookie:domain(<<"/">>)]))
     , ?assertError({badmatch, {invalid_cookie_name, "="}}, elli_cookie:delete("=", [elli_cookie:domain(<<"/">>)]))

     , ?assertMatch({_, <<"test=;Expires=Wed, 31 Dec 1969 23:00:00 GMT;Domain=/", _/binary>>}, elli_cookie:delete(<<"test">>, [elli_cookie:domain(<<"/">>)]))
     , ?assertMatch({_, <<"test=;Expires=Wed, 31 Dec 1969 23:00:00 GMT;Domain=example.com;Path=/hork", _/binary>>},
                     elli_cookie:delete(<<"test">>,
                                        [elli_cookie:domain(<<"example.com">>), elli_cookie:path(<<"/hork">>)]))
     , ?assertError({badmatch, {invalid_cookie_name, <<"=">>}},
                     elli_cookie:delete(<<"=">>,
                                        [elli_cookie:domain(<<"/">>)])).


valueHasEqual_test() ->
     ?assertMatch({<<"Set-Cookie">>, <<"name=val=3">>}, elli_cookie:new(<<"name">>, <<"val=3">>))
     , ?assertEqual([{<<"name">>, <<"val=3">>}], elli_cookie:parse(#req{headers=[{<<"Cookie">>, <<"name=val=3">>}]}))
     , ?assertMatch(<<"val=3">>, elli_cookie:get(<<"name">>, [{<<"name">>, <<"val=3">>}]))
     , ?assertMatch(<<"val=3==">>, elli_cookie:get(<<"name">>, [{<<"name">>, <<"val=3==">>}]))
     , ?assertError({badmatch, {invalid_cookie_name, <<"name=">>}},
                     elli_cookie:get(<<"name=">>, [{<<"name">>, <<"val=3==">>}])).
