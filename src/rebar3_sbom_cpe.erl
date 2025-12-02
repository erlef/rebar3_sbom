%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2025 Stritzinger GmbH

-module(rebar3_sbom_cpe).

-export([cpe/3]).

% Includes
-include("rebar3_sbom.hrl").

%--- Macros --------------------------------------------------------------------
-define(CPE_PREFIX, <<"cpe:", ?CPE_VERSION/binary>>).
% Includes the fields:
% - update
% - edition
% - language
% - target_sw
% - target_hw
% - other
-define(CPE_POSTFIX, <<":*:*:*:*:*:*:*">>).

% The CPE specs define 3 classes of parts:
% - a: application
% - o: operating system
% - h: hardware
% We only support application components for now.
-define(CPE_PART_APPLICATION, <<"a">>).

%--- API -----------------------------------------------------------------------

-spec cpe(Name, Version, Url) -> CPE when
    Name :: bitstring(),
    Version :: bitstring(),
    Url :: bitstring() | undefined,
    CPE :: bitstring().
cpe(Name, undefined, Url) ->
    cpe(Name, <<"*">>, Url);
cpe(<<"hex_core">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":hex:hex_core:", Version/bitstring,
        ?CPE_POSTFIX/binary>>;
cpe(<<"plug">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":elixir-plug:plug:",
        Version/bitstring, ?CPE_POSTFIX/binary>>;
cpe(<<"phoenix">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":phoenixframework:phoenix:",
        Version/bitstring, ?CPE_POSTFIX/binary>>;
cpe(<<"coherence">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":coherence_project:coherence:",
        Version/bitstring, ?CPE_POSTFIX/binary>>;
cpe(<<"xain">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":emetrotel:xain:", Version/bitstring,
        ?CPE_POSTFIX/binary>>;
cpe(<<"sweet_xml">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":kbrw:sweet_xml:", Version/bitstring,
        ?CPE_POSTFIX/binary>>;
cpe(<<"erlang/otp">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":erlang:erlang\/otp:",
        Version/bitstring, ?CPE_POSTFIX/binary>>;
cpe(<<"rebar3">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":erlang:rebar3:", Version/bitstring,
        ?CPE_POSTFIX/binary>>;
cpe(<<"elixir">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary, ":elixir-lang:elixir:",
        Version/bitstring, ?CPE_POSTFIX/binary>>;
cpe(_Name, _Version, undefined) ->
    undefined;
cpe(Name, Version, Url) ->
    Organization = github_url(Url),
    build_cpe(Organization, Name, Version).

%--- Private -------------------------------------------------------------------

-spec github_url(Url) -> Organization when
    Url :: bitstring(),
    Organization :: bitstring().
github_url(<<"https://github.com/", Rest/bitstring>>) ->
    [Organization | _] = string:split(Rest, "/"),
    Organization;
github_url(<<"git@github.com:", Rest/bitstring>>) ->
    [Organization | _] = string:split(Rest, "/"),
    Organization.

-spec build_cpe(Organization, Name, Version) -> CPE when
    Organization :: bitstring(),
    Name :: bitstring(),
    Version :: bitstring(),
    CPE :: bitstring().
build_cpe(Organization, Name, Version) ->
    <<?CPE_PREFIX/binary, ":a:", Organization/binary, ":", Name/binary, ":", Version/bitstring,
        ?CPE_POSTFIX/binary>>.
