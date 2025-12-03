%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2025 Stritzinger GmbH

-module(rebar3_sbom_test_utils).

-export([get_app_dir/2]).
-export([init_rebar_state/2]).
-export([build_dir_path/2]).

%--- Includes ------------------------------------------------------------------

-include_lib("common_test/include/ct.hrl").

%--- API -----------------------------------------------------------------------
get_app_dir(DataDir, AppName) ->
    SplitDataDir = filename:split(DataDir),
    JoinedParentDir = filename:join(lists:droplast(SplitDataDir)),
    AppDir = filename:join(JoinedParentDir, AppName),
    true = filelib:is_dir(AppDir),
    AppDir.

init_rebar_state(Config, AppName) ->
    DataDir = ?config(data_dir, Config),
    PrivDir = ?config(priv_dir, Config),
    AppDir = get_app_dir(DataDir, AppName),
    BaseDir = build_dir_path(PrivDir, AppName),
    State = rebar_state:new([
        {base_dir, BaseDir},
        {root_dir, AppDir}
    ]),
    RebarConfig = rebar_config:consult(AppDir),
    State2 = rebar_state:new(State, RebarConfig, AppDir),
    {ok, State3} = rebar3_sbom_prv:init(State2),
    add_fake_plugin_dep(State3, DataDir).

build_dir_path(PrivDir, AppName) ->
    filename:join([PrivDir, "_build_" ++ AppName]).

add_fake_plugin_dep(State, DataDir) ->
    SplitDataDir = filename:split(DataDir),
    [_ | ReversedPluginDir] = lists:dropwhile(
        fun(Dir) -> Dir =/= "_build" end, lists:reverse(SplitDataDir)
    ),
    PluginDir = filename:join(lists:reverse(ReversedPluginDir)),
    {ok, FakePluginEntry} = rebar_app_info:discover(PluginDir, State),
    FakePluginEntry2 = rebar_app_info:source(FakePluginEntry, checkout),
    rebar_state:all_plugin_deps(State, [FakePluginEntry2]).
