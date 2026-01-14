%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2019 Bram Verburg
%% SPDX-FileCopyrightText: 2022 lafirest
%% SPDX-FileCopyrightText: 2024 Stritzinger GmbH
%% SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation

-module(rebar3_sbom_cyclonedx).

-export([bom/5, bom/6, uuid/0]).

-include("rebar3_sbom.hrl").

bom(FileInfo, IsStrictVersion, App, Plugin, MetadataInfo) ->
    bom(FileInfo, IsStrictVersion, App, Plugin, uuid(), MetadataInfo).

bom({FilePath, _} = FileInfo, IsStrictVersion, App, Plugin, Serial, MetadataInfo) ->
    {AppInfo, RawComponents} = App,
    {PluginInfo, PluginDepsInfo} = Plugin,
    ValidRawComponents = lists:filter(fun(E) -> E =/= undefined end, RawComponents),
    % Filtering out rebar3_sbom from plugin dependencies to avoid duplicates in output
    ValidPluginDepsInfo = lists:filter(
        fun(E) ->
            E =/= undefined andalso proplists:get_value(name, E) =/= <<"rebar3_sbom">>
        end,
        PluginDepsInfo
    ),
    AllDeps = dependencies(ValidRawComponents) ++ dependencies(ValidPluginDepsInfo),
    SBoM0 = #sbom{
        serial = Serial,
        metadata = metadata(AppInfo, PluginInfo, MetadataInfo),
        components = components(ValidRawComponents) ++ components(ValidPluginDepsInfo),
        dependencies = [dependency(AppInfo), dependency(PluginInfo) | AllDeps]
    },
    % Normalize and remove duplicates where CycloneDX forbids them
    SBoM = normalize_sbom(SBoM0),
    try
        V = version(FileInfo, IsStrictVersion, SBoM),
        SBoM#sbom{version = V}
    catch
        _:Reason:_Stacktrace ->
            rebar_api:error(
                "scan file:~ts failed, reason:~p, will use the default version number ~p",
                [FilePath, Reason, ?DEFAULT_VERSION]
            ),
            SBoM
    end.

-spec metadata(App, Plugin, MetadataInfo) -> Metadata when
    App :: proplists:proplist(),
    Plugin :: proplists:proplist(),
    MetadataInfo :: proplists:proplist(),
    Metadata :: rebar3_sbom:metadata().
metadata(App, Plugin, MetadataInfo) ->
    #metadata{
        timestamp = calendar:system_time_to_rfc3339(erlang:system_time(second)),
        tools = [component(Plugin)],
        manufacturer = manufacturer(proplists:get_value(manufacturer, MetadataInfo, undefined)),
        authors = sbom_authors(proplists:get_value(author, MetadataInfo, undefined), App),
        component = component(App),
        licenses = sbom_licenses(proplists:get_value(licenses, MetadataInfo, undefined), App)
    }.

-spec sbom_authors(Author, App) -> Authors when
    Author :: undefined | string(),
    App :: proplists:proplist(),
    Authors :: [rebar3_sbom:individual()].
sbom_authors(undefined, App) ->
    case os:getenv("GITHUB_ACTOR") of
        false ->
            authors(App);
        Actor ->
            [#individual{name = Actor}]
    end;
sbom_authors(Author, _App) ->
    [#individual{name = Author}].

-spec sbom_licenses(LicensesIn, App) -> LicensesOut when
    LicensesIn :: undefined | [string()],
    App :: proplists:proplist(),
    LicensesOut :: [rebar3_sbom:license()].
sbom_licenses(undefined, App) ->
    component_field(licenses, App);
sbom_licenses(Licenses, _App) ->
    [license(License) || License <- Licenses].

components(RawComponents) ->
    [component(RawComponent) || RawComponent <- RawComponents].

component(RawComponent) ->
    #component{
        bom_ref = bom_ref_of_component(RawComponent),
        name = component_field(name, RawComponent),
        authors = authors(RawComponent),
        version = component_field(version, RawComponent),
        description = component_field(description, RawComponent),
        scope = component_field(scope, RawComponent),
        hashes = component_field(sha256, RawComponent),
        licenses = component_field(licenses, RawComponent),
        externalReferences = component_field(external_references, RawComponent),
        cpe = component_field(cpe, RawComponent),
        purl = component_field(purl, RawComponent)
    }.

component_field(licenses = Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        undefined ->
            [];
        Licenses ->
            [license(License) || License <- Licenses]
    end;
component_field(sha256 = Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        undefined ->
            [];
        Hash ->
            [#{alg => "SHA-256", hash => binary:bin_to_list(Hash)}]
    end;
component_field(external_references = Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        undefined ->
            [];
        [] ->
            [];
        References ->
            [
                #external_reference{type = Type, url = Url}
             || {Type, Url} <- maps:to_list(References)
            ]
    end;
component_field(Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        Value when is_binary(Value) ->
            binary:bin_to_list(Value);
        Else ->
            Else
    end.

license(Name) when is_binary(Name) ->
    license(binary:bin_to_list(Name));
license(Name) ->
    case rebar3_sbom_license:spdx_id(Name) of
        undefined ->
            #license{name = Name};
        SpdxId ->
            #license{id = SpdxId}
    end.

-spec manufacturer(ManufacturerIn) -> ManufacturerOut when
    ManufacturerIn :: undefined | map(),
    ManufacturerOut :: rebar3_sbom:organization() | undefined.
manufacturer(undefined) ->
    undefined;
manufacturer(Manufacturer) ->
    #organization{
        name = maps:get(name, Manufacturer, undefined),
        address = address(maps:get(address, Manufacturer, undefined)),
        url = maps:get(url, Manufacturer, []),
        contact = individuals(maps:get(contact, Manufacturer, undefined))
    }.

-spec address(undefined | map()) -> undefined | rebar3_sbom:address().
address(undefined) ->
    undefined;
address(AddressMap) ->
    #address{
        country = maps:get(country, AddressMap, undefined),
        region = maps:get(region, AddressMap, undefined),
        locality = maps:get(locality, AddressMap, undefined),
        post_office_box_number = maps:get(post_office_box_number, AddressMap, undefined),
        postal_code = maps:get(postal_code, AddressMap, undefined),
        street_address = maps:get(street_address, AddressMap, undefined)
    }.

-spec individuals(IndividualsIn) -> IndividualsOut when
    IndividualsIn :: [string()],
    IndividualsOut :: [rebar3_sbom:individual()].
individuals(undefined) ->
    [];
individuals(Individuals) ->
    lists:map(
        fun(Individual) ->
            #individual{
                name = maps:get(name, Individual, undefined),
                email = maps:get(email, Individual, undefined),
                phone = maps:get(phone, Individual, undefined)
            }
        end,
        Individuals
    ).

-spec authors(App) -> Authors when
    App :: proplists:proplist(),
    Authors :: [rebar3_sbom:individual()].
authors(App) ->
    [#individual{name = Name} || Name <- proplists:get_value(authors, App, [])].

uuid() ->
    [A, B, C, D, E] = [crypto:strong_rand_bytes(Len) || Len <- [4, 2, 2, 2, 6]],
    UUID = lists:join("-", [
        hex(Part)
     || Part <- [A, B, <<4:4, C:12/binary-unit:1>>, <<2:2, D:14/binary-unit:1>>, E]
    ]),
    "urn:uuid:" ++ UUID.

hex(Bin) ->
    string:lowercase(<<<<Hex>> || <<Nibble:4>> <= Bin, Hex <- integer_to_list(Nibble, 16)>>).

dependencies(RawComponents) ->
    [dependency(RawComponent) || RawComponent <- RawComponents].

dependency(RawComponent) ->
    RawDependencies = proplists:get_value(dependencies, RawComponent, []),
    #dependency{
        ref = bom_ref_of_component(RawComponent),
        dependencies = [dependency([{name, D}]) || D <- RawDependencies]
    }.

bom_ref_of_component(RawComponent) ->
    Name = proplists:get_value(name, RawComponent),
    lists:flatten(io_lib:format("ref_component_~ts", [Name])).

version({FilePath, Format}, IsStrictVersion, NewSBoM) ->
    case filelib:is_regular(FilePath) of
        true ->
            OldSBoM = decode(FilePath, Format),
            version(IsStrictVersion, {NewSBoM, OldSBoM});
        false ->
            rebar_api:info(
                "Using default SBoM version ~p: no previous SBoM file found.",
                [?DEFAULT_VERSION]
            ),
            ?DEFAULT_VERSION
    end.

-spec version(IsStrictVersion, {NewSBoM, OldSBoM}) -> Version when
    IsStrictVersion :: boolean(),
    NewSBoM :: rebar3_sbom:sbom(),
    OldSBoM :: rebar3_sbom:sbom(),
    Version :: integer().
version(_, {_, OldSBoM}) when OldSBoM#sbom.version =:= 0 ->
    rebar_api:info(
        "Using default SBoM version ~p: invalid version in previous SBoM file.",
        [?DEFAULT_VERSION]
    ),
    ?DEFAULT_VERSION;
version(IsStrictVersion, {_, OldSBoM}) when not (IsStrictVersion) ->
    rebar_api:info(
        "Incrementing the SBoM version unconditionally: strict_version is set to false.", []
    ),
    OldSBoM#sbom.version + 1;
version(IsStrictVersion, {NewSBoM, OldSBoM}) when IsStrictVersion ->
    case is_sbom_equal(NewSBoM, OldSBoM) of
        true ->
            rebar_api:info(
                "Not incrementing the SBoM version: new SBoM is equivalent to the old SBoM.", []
            ),
            OldSBoM#sbom.version;
        false ->
            rebar_api:info(
                "Incrementing the SBoM version: new SBoM is not equivalent to the old SBoM.", []
            ),
            OldSBoM#sbom.version + 1
    end.

is_sbom_equal(#sbom{components = NewComponents}, #sbom{components = OldComponents}) ->
    lists:all(fun(C) -> lists:member(C, NewComponents) end, OldComponents) andalso
        lists:all(fun(C) -> lists:member(C, OldComponents) end, NewComponents).

decode(FilePath, "xml") ->
    rebar3_sbom_xml:decode(FilePath);
decode(FilePath, "json") ->
    rebar3_sbom_json:decode(FilePath).

-spec normalize_sbom(rebar3_sbom:sbom()) -> rebar3_sbom:sbom().
normalize_sbom(#sbom{metadata = Metadata0, components = Components0, dependencies = Deps0} = S) ->
    Components = lists:map(fun normalize_component/1, dedup(Components0)),
    Metadata = normalize_metadata(Metadata0),
    Deps = normalize_deps(Deps0),
    S#sbom{metadata = Metadata, components = Components, dependencies = Deps}.

-spec normalize_metadata(rebar3_sbom:metadata()) -> rebar3_sbom:metadata().
normalize_metadata(#metadata{authors = Authors0, licenses = Licenses0} = M) ->
    M#metadata{authors = dedup(Authors0), licenses = dedup(Licenses0)}.

-spec normalize_component(rebar3_sbom:component()) -> rebar3_sbom:component().
normalize_component(#component{authors = Authors0, licenses = Licenses0} = C) ->
    C#component{authors = dedup(Authors0), licenses = dedup(Licenses0)}.

-spec normalize_deps([rebar3_sbom:dependency()]) -> [rebar3_sbom:dependency()].
normalize_deps(Deps0) ->
    Deps1 = [D#dependency{dependencies = normalize_deps(D#dependency.dependencies)} || D <- Deps0],
    dedup(Deps1).

-spec dedup([term()]) -> [term()].
dedup(List) when is_list(List) -> lists:uniq(List).
