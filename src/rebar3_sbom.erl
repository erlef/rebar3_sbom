%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2019 Bram Verburg
%% SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation

-module(rebar3_sbom).

-include("rebar3_sbom.hrl").

-export([init/1]).

-export_type([
    external_reference/0,
    individual/0,
    address/0,
    organization/0,
    license/0,
    component/0,
    metadata/0,
    dependency/0,
    sbom/0
]).

-type external_reference() :: #external_reference{}.
-type individual() :: #individual{}.
-type address() :: #address{}.
-type organization() :: #organization{}.
-type license() :: #license{}.
-type component() :: #component{}.
-type metadata() :: #metadata{}.
-type dependency() :: #dependency{}.
-type sbom() :: #sbom{}.

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    {ok, State1} = rebar3_sbom_prv:init(State),
    {ok, State1}.
