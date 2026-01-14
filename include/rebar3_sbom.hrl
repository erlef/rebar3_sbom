%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2024 Stritzinger GmbH

%--- Macros --------------------------------------------------------------------

-define(APP, "rebar3_sbom").
-define(DEFAULT_OUTPUT, "./bom.[xml|json]").
-define(DEFAULT_VERSION, 1).
-define(PROVIDER, sbom).
-define(DEPS, [lock]).
-define(SPEC_VERSION, <<"1.6">>).
-define(CPE_VERSION, <<"2.3">>).

%--- Types ---------------------------------------------------------------------

-type bom_ref() :: string().
% TODO: enumerate the valid SPDX licence IDs
-type spdx_licence_id() :: string().
-type properties() :: [{string(), string()}].
-type scope() :: required | optional | excluded.

%--- Records -------------------------------------------------------------------

-record(external_reference, {
    type :: string(),
    url :: string()
}).

% Alias Author, Contact
-record(individual, {
    bom_ref :: bom_ref() | undefined,
    name :: string() | undefined,
    email :: string() | undefined,
    phone :: string() | undefined
}).

-record(address, {
    bom_ref :: bom_ref() | undefined,
    country :: string() | undefined,
    region :: string() | undefined,
    locality :: string() | undefined,
    post_office_box_number :: string() | undefined,
    postal_code :: string() | undefined,
    street_address :: string() | undefined
}).

% Alias Manufacturer object
-record(organization, {
    bom_ref :: bom_ref() | undefined,
    name :: string() | undefined,
    address :: #address{} | undefined,
    url = [] :: [string()],
    contact = [] :: [#individual{}]
}).

% Not adding Text, URL, Licensing for now
-record(license, {
    bom_ref :: bom_ref() | undefined,
    id :: spdx_licence_id() | undefined,
    name :: string() | undefined,
    acknowledgement :: declared | concluded | undefined,
    properties = [] :: properties()
}).

-record(component, {
    type = "application",
    bom_ref :: string(),
    authors = [] :: [#{name := string()}],
    name :: string(),
    version :: string(),
    description :: string(),
    scope :: scope(),
    hashes = [] :: [#{alg := string(), hash := string()}],
    licenses = [] :: [#{name := string()} | #{id := string()}],
    externalReferences = [] :: [#external_reference{}],
    cpe :: string() | undefined,
    purl :: string()
}).

-record(metadata, {
    timestamp :: string(),
    component :: #component{},
    tools = [] :: [#component{}],
    manufacturer = undefined :: #organization{} | undefined,
    authors = [] :: [#individual{}],
    licenses = [] :: [#license{}],
    properties = [] :: properties()
}).

-record(dependency, {
    ref :: string(),
    dependencies = [] :: [#dependency{}]
}).

-record(sbom, {
    format = "CycloneDX" :: string(),
    version = ?DEFAULT_VERSION :: integer(),
    serial :: string() | undefined,
    metadata :: #metadata{} | undefined,
    components :: [#component{}],
    dependencies = [] :: [#dependency{}]
}).
