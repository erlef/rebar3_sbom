%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2024 Stritzinger GmbH
%% SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation

-module(rebar3_sbom_json).

-export([encode/1, decode/1]).

-include("rebar3_sbom.hrl").

-moduledoc "Encodes and decodes the SBoM to and from CycloneDX JSON.".

-define(SCHEMA, <<"http://cyclonedx.org/schema/bom-1.6.schema.json">>).

encode(SBoM) ->
    Content = sbom_to_json(SBoM),
    Opts = [
        native_forward_slash,
        native_utf8,
        canonical_form,
        {indent, 2},
        {space, 1}
    ],
    jsone:encode(Content, Opts).

decode(FilePath) ->
    % Note: This sets the SBoM version to 0 if the json file
    %       does not have a valid version.
    {ok, File} = file:read_file(FilePath),
    JsonTerm = jsone:decode(File),
    Version = maps:get(<<"version">>, JsonTerm, 0),
    Components = json_to_components(maps:get(<<"components">>, JsonTerm, [])),
    #sbom{version = Version, components = Components}.

% Encode -----------------------------------------------------------------------
sbom_to_json(#sbom{metadata = Metadata} = SBoM) ->
    #{
        '$schema' => ?SCHEMA,
        bomFormat => bin(SBoM#sbom.format),
        specVersion => ?SPEC_VERSION,
        serialNumber => bin(SBoM#sbom.serial),
        version => SBoM#sbom.version,
        metadata => metadata_to_json(Metadata),
        components => [component_to_json(C) || C <- SBoM#sbom.components],
        dependencies => [dependency_to_json(D) || D <- SBoM#sbom.dependencies]
    }.

component_to_json(C) ->
    prune_content(#{
        type => bin(C#component.type),
        'bom-ref' => bin(C#component.bom_ref),
        authors => individuals_to_json(C#component.authors),
        name => bin(C#component.name),
        version => bin(C#component.version),
        description => bin(C#component.description),
        scope => bin(C#component.scope),
        hashes => hashes_to_json(C#component.hashes),
        licenses => licenses_to_json(C#component.licenses),
        externalReferences => external_references_to_json(C#component.externalReferences),
        cpe => bin(C#component.cpe),
        purl => bin(C#component.purl)
    }).

prune_content(Component) ->
    maps:filter(fun(_, Value) -> Value =/= undefined end, Component).

-spec individuals_to_json([rebar3_sbom:individual()]) -> [#{name => binary()}].
individuals_to_json(Individuals) ->
    [individual_to_json(I) || I <- Individuals].

-spec individual_to_json(rebar3_sbom:individual()) -> #{name => binary()}.
individual_to_json(Individual) ->
    prune_content(#{
        name => bin(Individual#individual.name),
        email => bin(Individual#individual.email),
        phone => bin(Individual#individual.phone)
    }).

-spec metadata_to_json(rebar3_sbom:metadata()) -> map().
metadata_to_json(Metadata) ->
    prune_content(#{
        timestamp => bin(Metadata#metadata.timestamp),
        tools => #{components => [component_to_json(T) || T <- Metadata#metadata.tools]},
        component => component_to_json(Metadata#metadata.component),
        manufacturer => manufacturer_to_json(Metadata#metadata.manufacturer),
        authors => individuals_to_json(Metadata#metadata.authors),
        licenses => licenses_to_json(Metadata#metadata.licenses)
    }).

-spec manufacturer_to_json(rebar3_sbom:organization() | undefined) -> map() | undefined.
manufacturer_to_json(undefined) ->
    undefined;
manufacturer_to_json(Manufacturer) ->
    prune_content(#{
        name => bin(Manufacturer#organization.name),
        address => address_to_json(Manufacturer#organization.address),
        url => urls_to_json(Manufacturer#organization.url),
        contact => individuals_to_json(Manufacturer#organization.contact)
    }).

-spec address_to_json(rebar3_sbom:address()) -> map().
address_to_json(Address) ->
    prune_content(#{
        country => bin(Address#address.country),
        region => bin(Address#address.region),
        locality => bin(Address#address.locality),
        postOfficeBoxNumber => bin(Address#address.post_office_box_number),
        postalCode => bin(Address#address.postal_code),
        streetAddress => bin(Address#address.street_address)
    }).

-spec urls_to_json([string()]) -> [string()].
urls_to_json([]) ->
    undefined;
urls_to_json(Urls) ->
    [bin(Url) || Url <- Urls].

hashes_to_json(Hashes) ->
    [hash_to_json(H) || H <- Hashes].

hash_to_json(#{alg := Alg, hash := Hash}) ->
    #{alg => bin(Alg), content => bin(Hash)}.

external_references_to_json(ExternalReferences) ->
    [external_reference_to_json(R) || R <- ExternalReferences].

external_reference_to_json(#external_reference{type = Type, url = Url}) ->
    #{type => bin(Type), url => bin(Url)}.

licenses_to_json(Licenses) ->
    [license_to_json(L) || L <- Licenses].

license_to_json(License) ->
    #{
        license => prune_content(#{
            name => bin(License#license.name),
            id => bin(License#license.id)
        })
    }.

dependency_to_json(D) ->
    #{
        ref => bin(D#dependency.ref),
        dependsOn => [bin(SubD#dependency.ref) || SubD <- D#dependency.dependencies]
    }.

bin(undefined) ->
    undefined;
bin(Value) when is_list(Value) ->
    erlang:list_to_binary(Value);
bin(Value) ->
    Value.

% Decode -----------------------------------------------------------------------
json_to_components(Components) when is_list(Components) ->
    lists:map(fun json_to_components/1, Components);
json_to_components(C) ->
    #component{
        bom_ref = json_to_component_field(<<"bom-ref">>, C),
        authors = json_to_component_field(<<"authors">>, C),
        description = json_to_component_field(<<"description">>, C),
        scope = json_to_component_field(<<"scope">>, C),
        hashes = json_to_component_field(<<"hashes">>, C),
        licenses = json_to_component_field(<<"licenses">>, C),
        name = json_to_component_field(<<"name">>, C),
        cpe = json_to_component_field(<<"cpe">>, C),
        purl = json_to_component_field(<<"purl">>, C),
        type = json_to_component_field(<<"type">>, C),
        externalReferences = json_to_component_field(<<"externalReferences">>, C),
        version = json_to_component_field(<<"version">>, C)
    }.

json_to_component_field(<<"authors">> = F, Component) ->
    json_to_authors(maps:get(F, Component, undefined));
json_to_component_field(<<"hashes">> = F, Component) ->
    json_to_hashes(maps:get(F, Component, undefined));
json_to_component_field(<<"licenses">> = F, Component) ->
    json_to_licenses(maps:get(F, Component, undefined));
json_to_component_field(<<"externalReferences">> = F, Component) ->
    json_to_external_references(maps:get(F, Component, undefined));
json_to_component_field(<<"scope">> = F, Component) ->
    case maps:get(F, Component, undefined) of
        undefined ->
            undefined;
        Scope ->
            case Scope of
                <<"required">> -> required;
                <<"optional">> -> optional;
                <<"excluded">> -> excluded
            end
    end;
json_to_component_field(FieldName, Component) ->
    str(maps:get(FieldName, Component, undefined)).

json_to_authors(undefined) ->
    undefined;
json_to_authors(Authors) ->
    [json_to_author(A) || A <- Authors].

json_to_author(Author) ->
    #individual{
        name = str(maps:get(<<"name">>, Author, undefined)),
        email = str(maps:get(<<"email">>, Author, undefined)),
        phone = str(maps:get(<<"phone">>, Author, undefined))
    }.

json_to_hashes(undefined) ->
    undefined;
json_to_hashes(Hashes) ->
    [json_to_hash(H) || H <- Hashes].

json_to_hash(#{<<"alg">> := Alg, <<"content">> := Content}) ->
    #{alg => str(Alg), hash => str(Content)}.

json_to_licenses(undefined) ->
    undefined;
json_to_licenses(Licenses) ->
    [json_to_license(L) || L <- Licenses].

json_to_license(#{<<"license">> := License}) ->
    #license{
        id = str(maps:get(<<"id">>, License, undefined)),
        name = str(maps:get(<<"name">>, License, undefined))
    }.

json_to_external_references(undefined) ->
    undefined;
json_to_external_references(ExternalReferences) ->
    [json_to_external_reference(R) || R <- ExternalReferences].

json_to_external_reference(#{<<"type">> := Type, <<"url">> := Url}) ->
    #external_reference{type = str(Type), url = str(Url)}.

str(undefined) ->
    undefined;
str(Value) when is_binary(Value) ->
    erlang:binary_to_list(Value);
str(Value) ->
    Value.
