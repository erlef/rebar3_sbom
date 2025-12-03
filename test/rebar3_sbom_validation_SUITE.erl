%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2025 Stritzinger GmbH

-module(rebar3_sbom_validation_SUITE).

% CT Exports
-export([all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

% Testcases
-export([validate_json_test/1]).
-export([validate_xml_test/1]).

% Includes
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%--- Macros --------------------------------------------------------------------

-define(VALIDATION_SBOM_JSON, "validation_sbom.json").
-define(VALIDATION_SBOM_XML, "validation_sbom.xml").

%--- Common test functions -----------------------------------------------------

% all() ->
%     [validate_json_test,
%     validate_xml_test].
all() ->
    [validate_json_test].

init_per_suite(Config) ->
    application:load(rebar3_sbom),
    [{cyclonedx_cli_path, cyclonedx_cli_path()} | Config].

end_per_suite(Config) ->
    Config.

init_per_testcase(validate_json_test, Config) ->
    State = rebar3_sbom_test_utils:init_rebar_state(Config, "basic_app"),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, ?VALIDATION_SBOM_JSON),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f", "-a", "Jane Doe"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    [{sbom_path, SBoMPath} | Config];
init_per_testcase(validate_xml_test, Config) ->
    State = rebar3_sbom_test_utils:init_rebar_state(Config, "basic_app"),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, ?VALIDATION_SBOM_XML),
    Cmd = ["sbom", "-F", "xml", "-o", SBoMPath, "-V", "false", "-f", "-a", "Jane Doe"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    [{sbom_path, SBoMPath} | Config];
init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, Config) ->
    Config.

%--- Testcases ----------------------------------------------------------------
validate_json_test(Config) ->
    SBoMPath = ?config(sbom_path, Config),
    CycloneDXCLIPath = ?config(cyclonedx_cli_path, Config),
    Cmd = [CycloneDXCLIPath, "validate", "--input-file", SBoMPath, "--input-format", "json"],
    Output = os:cmd(lists:join(" ", Cmd)),
    ?assertEqual("BOM validated successfully.\n", Output).

validate_xml_test(Config) ->
    SBoMPath = ?config(sbom_path, Config),
    CycloneDXCLIPath = ?config(cyclonedx_cli_path, Config),
    Cmd = [CycloneDXCLIPath, "validate", "--input-file", SBoMPath, "--input-format", "xml"],
    {ok, Output} = os:cmd(Cmd),
    ?assertEqual(0, Output).

%--- Private -------------------------------------------------------------------

cyclonedx_cli_path() ->
    Names = ["cyclonedx-cli", "cyclonedx"],
    Paths = [os:find_executable(Name) || Name <- Names],
    case lists:filter(fun(Path) -> Path =/= false end, Paths) of
        [] ->
            ct:fail("CycloneDX CLI not found");
        [ValidPath | _] ->
            ValidPath
    end.
