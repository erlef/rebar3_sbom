-module(rebar3_sbom_cpe_SUITE).

% CT Exports
-export([all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

% Testcases
-export([hex_core_cpe_test/1]).
-export([plug_cpe_test/1]).
-export([phoenix_cpe_test/1]).
-export([coherence_cpe_test/1]).
-export([xain_cpe_test/1]).
-export([sweet_xml_cpe_test/1]).
-export([erlang_otp_cpe_test/1]).
-export([rebar3_cpe_test/1]).
-export([elixir_cpe_test/1]).
-export([default_behavior_test/1]).
-export([no_url_test/1]).

% Includes
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%--- Common test functions -----------------------------------------------------

all() -> [hex_core_cpe_test,
          plug_cpe_test,
          phoenix_cpe_test,
          coherence_cpe_test,
          xain_cpe_test,
          sweet_xml_cpe_test,
          erlang_otp_cpe_test,
          rebar3_cpe_test,
          elixir_cpe_test,
          default_behavior_test,
          no_url_test].

init_per_suite(Config) ->
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _Config) ->
    ok.

%--- Test cases ----------------------------------------------------------------

hex_core_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"hex_core">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:hex:hex_core:1.0.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"hex_core">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:hex:hex_core:*:*:*:*:*:*:*:*">>, CPENoVersion).

plug_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"plug">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:elixir-plug:plug:1.0.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"plug">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:elixir-plug:plug:*:*:*:*:*:*:*:*">>, CPENoVersion).

phoenix_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"phoenix">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:phoenixframework:phoenix:1.0.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"phoenix">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:phoenixframework:phoenix:*:*:*:*:*:*:*:*">>, CPENoVersion).

coherence_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"coherence">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:coherence_project:coherence:1.0.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"coherence">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:coherence_project:coherence:*:*:*:*:*:*:*:*">>, CPENoVersion).

xain_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"xain">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:emetrotel:xain:1.0.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"xain">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:emetrotel:xain:*:*:*:*:*:*:*:*">>, CPENoVersion).

sweet_xml_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"sweet_xml">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:kbrw:sweet_xml:1.0.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"sweet_xml">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:kbrw:sweet_xml:*:*:*:*:*:*:*:*">>, CPENoVersion).

erlang_otp_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"erlang/otp">>, <<"28.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:erlang:erlang\/otp:28.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"erlang/otp">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*">>, CPENoVersion).

rebar3_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"rebar3">>, <<"3.14.1">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:erlang:rebar3:3.14.1:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"rebar3">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:erlang:rebar3:*:*:*:*:*:*:*:*">>, CPENoVersion).

elixir_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"elixir">>, <<"1.19.3">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:elixir-lang:elixir:1.19.3:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"elixir">>, undefined, undefined),
    ?assertEqual(<<"cpe:2.3:a:elixir-lang:elixir:*:*:*:*:*:*:*:*">>, CPENoVersion).

default_behavior_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"my_package">>, <<"1.0.0">>, <<"https://github.com/my_org/my_package">>),
    ?assertEqual(<<"cpe:2.3:a:my_org:my_package:1.0.0:*:*:*:*:*:*:*">>, CPE),
    CPENoVersion = rebar3_sbom_cpe:cpe(<<"my_package">>, undefined, <<"https://github.com/my_org/my_package">>),
    ?assertEqual(<<"cpe:2.3:a:my_org:my_package:*:*:*:*:*:*:*:*">>, CPENoVersion).

no_url_test(_) ->
    CPE = rebar3_sbom_cpe:cpe(<<"non_hex_package">>, <<"1.0.0">>, undefined),
    ?assertEqual(undefined, CPE).
