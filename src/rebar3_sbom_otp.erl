%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(rebar3_sbom_otp).

-export([otp_components/0, otp_components/1]).

-include("rebar3_sbom.hrl").

-define(OTP_GITHUB, <<"https://github.com/erlang/otp">>).

%% Returns OTP/ERTS component info in the same proplist format as dep_info.
-spec otp_components() -> [proplists:proplist()].
otp_components() ->
    otp_components(otp_apps()).

-spec otp_components(Apps :: [atom()]) -> [proplists:proplist()].
otp_components(Apps) ->
    OtpRelease = erlang:system_info(otp_release),
    ErtsVersion = erlang:system_info(version),
    OtpComponent = otp_component(OtpRelease),
    ErtsComponent = erts_component(ErtsVersion, OtpRelease),
    AppComponents = [app_component(App, OtpRelease) || App <- Apps],
    [OtpComponent, ErtsComponent | AppComponents].

%% Top-level Erlang/OTP component
otp_component(OtpRelease) ->
    Name = <<"erlang/otp">>,
    Version = list_to_binary(OtpRelease),
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:otp_runtime(Name, Version, ?OTP_GITHUB)},
        {cpe, rebar3_sbom_cpe:cpe(Name, Version, ?OTP_GITHUB)},
        {authors, []},
        {description, <<"Erlang/OTP">>},
        {licenses, [<<"Apache-2.0">>]},
        {external_references, #{"vcs" => binary_to_list(?OTP_GITHUB)}},
        {dependencies, []},
        {scope, required}
    ].

%% ERTS component
erts_component(ErtsVersion, OtpRelease) ->
    Name = <<"erts">>,
    Version = list_to_binary(ErtsVersion),
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:otp_runtime(Name, Version, ?OTP_GITHUB)},
        {cpe, rebar3_sbom_cpe:cpe(<<"erlang/otp">>, list_to_binary(OtpRelease), ?OTP_GITHUB)},
        {authors, []},
        {description, <<"Erlang Runtime System">>},
        {licenses, [<<"Apache-2.0">>]},
        {external_references, #{"vcs" => binary_to_list(?OTP_GITHUB)}},
        {dependencies, []},
        {scope, required}
    ].

%% Individual OTP application component
app_component(App, OtpRelease) ->
    Name = atom_to_binary(App),
    Version =
        case application:get_key(App, vsn) of
            {ok, Vsn} -> list_to_binary(Vsn);
            undefined -> list_to_binary(OtpRelease)
        end,
    Description =
        case application:get_key(App, description) of
            {ok, Desc} -> unicode:characters_to_binary(Desc);
            undefined -> <<>>
        end,
    Licenses =
        case application:get_key(App, licenses) of
            {ok, L} -> [unicode:characters_to_binary(Li) || Li <- L];
            undefined -> [<<"Apache-2.0">>]
        end,
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:otp_runtime(Name, Version, ?OTP_GITHUB)},
        {cpe, rebar3_sbom_cpe:cpe(<<"erlang/otp">>, list_to_binary(OtpRelease), ?OTP_GITHUB)},
        {authors, []},
        {description, Description},
        {licenses, Licenses},
        {external_references, #{"vcs" => binary_to_list(?OTP_GITHUB)}},
        {dependencies, []},
        {scope, required}
    ].

%% Returns OTP apps actually used by the project's dependency tree.
%% These are the standard OTP applications that come bundled with Erlang.
-spec otp_apps() -> [atom()].
otp_apps() ->
    OtpLib = code:lib_dir(),
    AllLoaded = [App || {App, _, _} <- application:loaded_applications()],
    [App || App <- AllLoaded, is_otp_app(App, OtpLib)].

-spec is_otp_app(atom(), file:filename()) -> boolean().
is_otp_app(App, OtpLib) ->
    case code:lib_dir(App) of
        {error, _} -> false;
        Dir -> lists:prefix(OtpLib, Dir)
    end.
