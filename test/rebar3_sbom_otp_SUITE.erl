%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(rebar3_sbom_otp_SUITE).

-export([all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).

%% Unit tests
-export([otp_components_returns_list_test/1]).
-export([otp_component_present_test/1]).
-export([erts_component_present_test/1]).
-export([otp_component_has_correct_version_test/1]).
-export([erts_component_has_correct_version_test/1]).
-export([otp_component_has_purl_test/1]).
-export([erts_component_has_purl_test/1]).
-export([otp_component_has_cpe_test/1]).
-export([erts_component_has_cpe_test/1]).
-export([otp_component_has_license_test/1]).
-export([otp_component_has_external_references_test/1]).
-export([app_components_present_test/1]).
-export([app_component_has_purl_test/1]).
-export([app_component_has_cpe_test/1]).
-export([app_component_has_version_test/1]).
-export([custom_apps_list_test/1]).

%% Integration tests
-export([include_otp_flag_test/1]).
-export([otp_not_included_by_default_test/1]).
-export([otp_components_valid_json_test/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("rebar3_sbom/include/rebar3_sbom.hrl").

-define(PURL_REGEX, "^pkg:[a-z][a-z0-9+.-]*/([^/@?#]+/)*[^/@?#]+(@[^?#]+)?(\\?[^#]+)?(#.+)?$").
-define(CPE_REGEX,
    "^cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){4}$"
).

all() ->
    [
        {group, unit},
        {group, integration}
    ].

groups() ->
    [
        {unit, [], [
            otp_components_returns_list_test,
            otp_component_present_test,
            erts_component_present_test,
            otp_component_has_correct_version_test,
            erts_component_has_correct_version_test,
            otp_component_has_purl_test,
            erts_component_has_purl_test,
            otp_component_has_cpe_test,
            erts_component_has_cpe_test,
            otp_component_has_license_test,
            otp_component_has_external_references_test,
            app_components_present_test,
            app_component_has_purl_test,
            app_component_has_cpe_test,
            app_component_has_version_test,
            custom_apps_list_test
        ]},
        {integration, [], [
            include_otp_flag_test,
            otp_not_included_by_default_test,
            otp_components_valid_json_test
        ]}
    ].

init_per_suite(Config) ->
    application:load(rebar3_sbom),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(unit, Config) ->
    Components = rebar3_sbom_otp:otp_components(),
    [{otp_components, Components} | Config];
init_per_group(integration, Config) ->
    Config;
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _Config) ->
    ok.

%% --- Unit tests ---

otp_components_returns_list_test(Config) ->
    Components = ?config(otp_components, Config),
    ?assert(is_list(Components)),
    ?assert(length(Components) >= 2).

otp_component_present_test(Config) ->
    Components = ?config(otp_components, Config),
    OtpComponent = find_component(<<"erlang/otp">>, Components),
    ?assertNotEqual(undefined, OtpComponent).

erts_component_present_test(Config) ->
    Components = ?config(otp_components, Config),
    ErtsComponent = find_component(<<"erts">>, Components),
    ?assertNotEqual(undefined, ErtsComponent).

otp_component_has_correct_version_test(Config) ->
    Components = ?config(otp_components, Config),
    OtpComponent = find_component(<<"erlang/otp">>, Components),
    Version = proplists:get_value(version, OtpComponent),
    ExpectedVersion = list_to_binary(erlang:system_info(otp_release)),
    ?assertEqual(ExpectedVersion, Version).

erts_component_has_correct_version_test(Config) ->
    Components = ?config(otp_components, Config),
    ErtsComponent = find_component(<<"erts">>, Components),
    Version = proplists:get_value(version, ErtsComponent),
    ExpectedVersion = list_to_binary(erlang:system_info(version)),
    ?assertEqual(ExpectedVersion, Version).

otp_component_has_purl_test(Config) ->
    Components = ?config(otp_components, Config),
    OtpComponent = find_component(<<"erlang/otp">>, Components),
    Purl = proplists:get_value(purl, OtpComponent),
    ?assertNotEqual(undefined, Purl),
    ?assertNotEqual(nomatch, re:run(Purl, ?PURL_REGEX)).

erts_component_has_purl_test(Config) ->
    Components = ?config(otp_components, Config),
    ErtsComponent = find_component(<<"erts">>, Components),
    Purl = proplists:get_value(purl, ErtsComponent),
    ?assertNotEqual(undefined, Purl),
    ?assertNotEqual(nomatch, re:run(Purl, ?PURL_REGEX)).

otp_component_has_cpe_test(Config) ->
    Components = ?config(otp_components, Config),
    OtpComponent = find_component(<<"erlang/otp">>, Components),
    Cpe = proplists:get_value(cpe, OtpComponent),
    ?assertNotEqual(undefined, Cpe),
    OtpRelease = list_to_binary(erlang:system_info(otp_release)),
    Expected = <<"cpe:2.3:a:erlang:erlang/otp:", OtpRelease/binary, ":*:*:*:*:*:*:*">>,
    ?assertEqual(Expected, Cpe).

erts_component_has_cpe_test(Config) ->
    Components = ?config(otp_components, Config),
    ErtsComponent = find_component(<<"erts">>, Components),
    Cpe = proplists:get_value(cpe, ErtsComponent),
    ?assertNotEqual(undefined, Cpe),
    %% ERTS uses the erlang/otp CPE with the OTP release version
    OtpRelease = list_to_binary(erlang:system_info(otp_release)),
    Expected = <<"cpe:2.3:a:erlang:erlang/otp:", OtpRelease/binary, ":*:*:*:*:*:*:*">>,
    ?assertEqual(Expected, Cpe).

otp_component_has_license_test(Config) ->
    Components = ?config(otp_components, Config),
    OtpComponent = find_component(<<"erlang/otp">>, Components),
    Licenses = proplists:get_value(licenses, OtpComponent),
    ?assertMatch([_ | _], Licenses).

otp_component_has_external_references_test(Config) ->
    Components = ?config(otp_components, Config),
    OtpComponent = find_component(<<"erlang/otp">>, Components),
    Refs = proplists:get_value(external_references, OtpComponent),
    ?assert(is_map(Refs)),
    ?assert(maps:is_key("vcs", Refs)).

app_components_present_test(Config) ->
    Components = ?config(otp_components, Config),
    %% kernel and stdlib should always be present
    KernelComponent = find_component(<<"kernel">>, Components),
    StdlibComponent = find_component(<<"stdlib">>, Components),
    ?assertNotEqual(undefined, KernelComponent),
    ?assertNotEqual(undefined, StdlibComponent).

app_component_has_purl_test(Config) ->
    Components = ?config(otp_components, Config),
    KernelComponent = find_component(<<"kernel">>, Components),
    Purl = proplists:get_value(purl, KernelComponent),
    ?assertNotEqual(undefined, Purl),
    ?assertNotEqual(nomatch, re:run(Purl, ?PURL_REGEX)).

app_component_has_cpe_test(Config) ->
    Components = ?config(otp_components, Config),
    KernelComponent = find_component(<<"kernel">>, Components),
    Cpe = proplists:get_value(cpe, KernelComponent),
    ?assertNotEqual(undefined, Cpe),
    %% OTP app components share the erlang/otp CPE
    OtpRelease = list_to_binary(erlang:system_info(otp_release)),
    Expected = <<"cpe:2.3:a:erlang:erlang/otp:", OtpRelease/binary, ":*:*:*:*:*:*:*">>,
    ?assertEqual(Expected, Cpe).

app_component_has_version_test(Config) ->
    Components = ?config(otp_components, Config),
    KernelComponent = find_component(<<"kernel">>, Components),
    Version = proplists:get_value(version, KernelComponent),
    ?assertNotEqual(undefined, Version),
    ?assert(is_binary(Version)),
    ?assert(byte_size(Version) > 0).

custom_apps_list_test(_Config) ->
    Components = rebar3_sbom_otp:otp_components([kernel, stdlib]),
    %% Should have erlang/otp + erts + kernel + stdlib = 4
    ?assertEqual(4, length(Components)),
    Names = [proplists:get_value(name, C) || C <- Components],
    ?assert(lists:member(<<"erlang/otp">>, Names)),
    ?assert(lists:member(<<"erts">>, Names)),
    ?assert(lists:member(<<"kernel">>, Names)),
    ?assert(lists:member(<<"stdlib">>, Names)).

%% --- Integration tests ---

include_otp_flag_test(Config) ->
    State = rebar3_sbom_test_utils:init_rebar_state(Config, "basic_app"),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, "otp_flag_sbom.json"),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f", "--include-otp"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    SBoMJSON = json:decode(File),
    #{<<"components">> := Components} = SBoMJSON,
    Names = [maps:get(<<"name">>, C) || C <- Components],
    ?assert(lists:member(<<"erlang/otp">>, Names), "erlang/otp component missing"),
    ?assert(lists:member(<<"erts">>, Names), "erts component missing"),
    ?assert(lists:member(<<"kernel">>, Names), "kernel component missing"),
    ?assert(lists:member(<<"stdlib">>, Names), "stdlib component missing"),
    %% Verify OTP components have proper CPE
    OtpComponent = find_json_component(<<"erlang/otp">>, Components),
    ?assertMatch(#{<<"cpe">> := _}, OtpComponent),
    #{<<"cpe">> := OtpCpe} = OtpComponent,
    OtpRelease = list_to_binary(erlang:system_info(otp_release)),
    ExpectedCpe = <<"cpe:2.3:a:erlang:erlang/otp:", OtpRelease/binary, ":*:*:*:*:*:*:*">>,
    ?assertEqual(ExpectedCpe, OtpCpe),
    %% Verify OTP components have proper PURL
    ?assertMatch(#{<<"purl">> := _}, OtpComponent),
    #{<<"purl">> := OtpPurl} = OtpComponent,
    ?assertNotEqual(nomatch, re:run(OtpPurl, ?PURL_REGEX)).

otp_not_included_by_default_test(Config) ->
    State = rebar3_sbom_test_utils:init_rebar_state(Config, "basic_app"),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, "no_otp_sbom.json"),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    SBoMJSON = json:decode(File),
    #{<<"components">> := Components} = SBoMJSON,
    Names = [maps:get(<<"name">>, C) || C <- Components],
    ?assertNot(
        lists:member(<<"erlang/otp">>, Names), "erlang/otp should not be present by default"
    ),
    ?assertNot(lists:member(<<"erts">>, Names), "erts should not be present by default").

otp_components_valid_json_test(Config) ->
    State = rebar3_sbom_test_utils:init_rebar_state(Config, "basic_app"),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, "otp_valid_sbom.json"),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f", "--include-otp"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    SBoMJSON = json:decode(File),
    %% Verify basic structure is valid
    ?assertMatch(#{<<"bomFormat">> := <<"CycloneDX">>}, SBoMJSON),
    ?assertMatch(#{<<"specVersion">> := _}, SBoMJSON),
    #{<<"components">> := Components} = SBoMJSON,
    %% Every OTP component should have required fields
    OtpNames = [<<"erlang/otp">>, <<"erts">>, <<"kernel">>, <<"stdlib">>],
    lists:foreach(
        fun(Name) ->
            case find_json_component(Name, Components) of
                undefined ->
                    ct:fail("Missing OTP component: ~s", [Name]);
                Component ->
                    ?assertMatch(#{<<"type">> := <<"application">>}, Component),
                    ?assertMatch(#{<<"name">> := _}, Component),
                    ?assertMatch(#{<<"version">> := _}, Component),
                    ?assertMatch(#{<<"purl">> := _}, Component),
                    ?assertMatch(#{<<"scope">> := <<"required">>}, Component),
                    ?assertMatch(#{<<"licenses">> := [_ | _]}, Component)
            end
        end,
        OtpNames
    ).

%% --- Helpers ---

find_component(Name, Components) ->
    case
        lists:search(
            fun(C) -> proplists:get_value(name, C) =:= Name end,
            Components
        )
    of
        {value, C} -> C;
        false -> undefined
    end.

find_json_component(Name, Components) ->
    case
        lists:search(
            fun(C) -> maps:get(<<"name">>, C, undefined) =:= Name end,
            Components
        )
    of
        {value, C} -> C;
        false -> undefined
    end.
