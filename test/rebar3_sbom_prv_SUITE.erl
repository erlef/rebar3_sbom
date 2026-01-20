%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation

-module(rebar3_sbom_prv_SUITE).

-export([all/0]).
-export([init_per_suite/1, end_per_suite/1]).

-export([version_flag_test/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [version_flag_test].

init_per_suite(Config) ->
    application:load(rebar3_sbom),
    {ok, PluginVersion} = application:get_key(rebar3_sbom, vsn),
    [{plugin_version, list_to_binary(PluginVersion)} | Config].

end_per_suite(_Config) ->
    ok.

version_flag_test(Config) ->
    State = rebar3_sbom_test_utils:init_rebar_state(Config, "basic_app"),
    ExpectedVersion = ?config(plugin_version, Config),
    ExpectedSuffix = "rebar3_sbom " ++ binary_to_list(ExpectedVersion) ++ "\n",
    ct:capture_start(),
    try
        rebar3:run(State, ["sbom", "--version"])
    after
        ct:capture_stop()
    end,
    Output = lists:flatten(ct:capture_get([])),
    ?assert(
        lists:suffix(ExpectedSuffix, Output),
        "Expected output to end with: " ++ ExpectedSuffix ++ " but got: " ++ Output
    ).
