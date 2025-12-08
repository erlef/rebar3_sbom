%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2024 Stritzinger GmbH

-module(rebar3_sbom_xml).

-export([encode/1, decode/1]).

-include("rebar3_sbom.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-define(XMLNS, "http://cyclonedx.org/schema/bom/1.6").
-define(XMLNS_XSI, "http://www.w3.org/2001/XMLSchema-instance").
-define(XSI_SCHEMA_LOC,
    "http://cyclonedx.org/schema/bom/1.6 https://cyclonedx.org/schema/bom-1.6.xsd"
).

encode(SBoM) ->
    Content = sbom_to_xml(SBoM),
    xmerl:export_simple([Content], xmerl_xml).

decode(FilePath) ->
    % Note: This sets the SBoM version to 0 if the xml file
    %       does not have a valid version.
    {SBoM, _} = xmerl_scan:file(FilePath),
    Version = xml_to_bom_version(SBoM, 0),
    Components = [xml_to_component(C) || C <- xpath("/bom/components/component", SBoM)],
    #sbom{version = Version, components = Components}.

% Encode -----------------------------------------------------------------------
xml_to_bom_version(Xml, Default) ->
    case xpath("/bom/@version", Xml) of
        [Attr] ->
            erlang:list_to_integer(Attr#xmlAttribute.value);
        [] ->
            Default
    end.

sbom_to_xml(#sbom{metadata = Metadata} = SBoM) ->
    {
        bom,
        [
            {xmlns, ?XMLNS},
            {'xmlns:xsi', ?XMLNS_XSI},
            {'xsi:schemaLocation', ?XSI_SCHEMA_LOC},
            {version, SBoM#sbom.version},
            {serialNumber, SBoM#sbom.serial}
        ],
        [
            {metadata, metadata_to_xml(Metadata)},
            {components, [component_to_xml(C) || C <- SBoM#sbom.components]},
            {dependencies, [dependency_to_xml(D) || D <- SBoM#sbom.dependencies]}
        ]
    }.

metadata_to_xml(Metadata) ->
    Content = prune_content([
        {timestamp, [Metadata#metadata.timestamp]},
        {tools, [tools_to_xml(Metadata#metadata.tools)]},
        component_field_to_xml(authors, Metadata#metadata.authors),
        component_to_xml(Metadata#metadata.component),
        organization_to_xml(manufacturer, Metadata#metadata.manufacturer),
        component_field_to_xml(licenses, Metadata#metadata.licenses)
    ]),
    Content.

tools_to_xml(Tools) ->
    {components, [component_to_xml(Tool) || Tool <- Tools]}.

organization_to_xml(OrganizationType, undefined) ->
    {OrganizationType, [undefined]};
organization_to_xml(OrganizationType, Organization) ->
    Content = prune_content(
        [
            {name, [Organization#organization.name]},
            address_to_xml(Organization#organization.address)
        ] ++ [{url, [Url]} || Url <- Organization#organization.url] ++
            [individual_to_xml(contact, Contact) || Contact <- Organization#organization.contact]
    ),
    {OrganizationType, Content}.

address_to_xml(Address) ->
    Content = prune_content([
        {country, [Address#address.country]},
        {region, [Address#address.region]},
        {locality, [Address#address.locality]},
        {postOfficeBoxNumber, [Address#address.post_office_box_number]},
        {postalCode, [Address#address.postal_code]},
        {streetAddress, [Address#address.street_address]}
    ]),
    {address, Content}.

component_to_xml(C) ->
    Attributes = [{type, C#component.type}, {'bom-ref', C#component.bom_ref}],
    Content = prune_content([
        component_field_to_xml(authors, C#component.authors),
        component_field_to_xml(name, C#component.name),
        component_field_to_xml(version, C#component.version),
        component_field_to_xml(description, C#component.description),
        component_field_to_xml(scope, C#component.scope),
        component_field_to_xml(hashes, C#component.hashes),
        component_field_to_xml(licenses, C#component.licenses),
        component_field_to_xml(cpe, C#component.cpe),
        component_field_to_xml(purl, C#component.purl),
        component_field_to_xml(externalReferences, C#component.externalReferences)
    ]),
    {component, Attributes, Content}.

prune_content(Content) ->
    lists:filter(
        fun
            ({_, [Value]}) -> Value =/= undefined;
            (Field) -> Field =/= undefined
        end,
        Content
    ).

component_field_to_xml(authors, Authors) ->
    {authors, [individual_to_xml(author, Author) || Author <- Authors]};
component_field_to_xml(hashes, Hashes) ->
    {hashes, [hash_to_xml(Hash) || Hash <- Hashes]};
component_field_to_xml(licenses, Licenses) ->
    {licenses, [license_to_xml(License) || License <- Licenses]};
component_field_to_xml(externalReferences, ExternalReferences) ->
    {externalReferences, [external_reference_to_xml(Ref) || Ref <- ExternalReferences]};
component_field_to_xml(scope, Scope) ->
    {scope, [atom_to_list(Scope)]};
component_field_to_xml(FieldName, Value) ->
    {FieldName, [Value]}.

individual_to_xml(IndividualType, Individual) ->
    Content = prune_content([
        {name, [Individual#individual.name]},
        {email, [Individual#individual.email]},
        {phone, [Individual#individual.phone]}
    ]),
    {IndividualType, Content}.

hash_to_xml(#{alg := Alg, hash := Hash}) ->
    {hash, [{alg, Alg}], [Hash]}.

license_to_xml(#{name := Name}) ->
    {license, [{name, [Name]}]};
license_to_xml(#{id := Id}) ->
    {license, [{id, [Id]}]}.

external_reference_to_xml(#external_reference{type = Type, url = Url}) ->
    {reference, [{type, Type}], [{url, [Url]}]}.

dependency_to_xml(Dependency) ->
    {dependency, [{ref, Dependency#dependency.ref}], [
        dependency_to_xml(D)
     || D <- Dependency#dependency.dependencies
    ]}.

% Decode -----------------------------------------------------------------------
xml_to_component(Component) ->
    [#xmlAttribute{value = Type}] = xpath("/component/@type", Component),
    [#xmlAttribute{value = BomRef}] = xpath("/component/@bom-ref", Component),
    Authors = [xml_to_author(A) || A <- xpath("/component/authors/author", Component)],
    Name = xpath("/component/name/text()", Component),
    Version = xpath("/component/version/text()", Component),
    Description = xpath("/component/description/text()", Component),
    Scope = xpath("/component/scope/text()", Component),
    Purl = xpath("/component/purl/text()", Component),
    Cpe = xpath("/component/cpe/text()", Component),
    Hashes = [xml_to_hash(H) || H <- xpath("/component/hashes/hash", Component)],
    ExternalReferences = [
        xml_to_external_reference(Ref)
     || Ref <- xpath("/component/externalReferences/reference", Component)
    ],
    Licenses = [xml_to_license(L) || L <- xpath("/component/licenses/license", Component)],
    #component{
        type = Type,
        bom_ref = BomRef,
        authors = Authors,
        name = xml_to_component_field(Name),
        version = xml_to_component_field(Version),
        description = xml_to_component_field(Description),
        scope = xml_to_component_field(Scope),
        purl = xml_to_component_field(Purl),
        cpe = xml_to_component_field(Cpe),
        hashes = Hashes,
        licenses = Licenses,
        externalReferences = ExternalReferences
    }.

xml_to_component_field([]) ->
    undefined;
xml_to_component_field([#xmlText{parents = [{scope, _} | _], value = Value}]) ->
    case Value of
        "required" -> required;
        "optional" -> optional;
        "excluded" -> excluded
    end;
xml_to_component_field([#xmlText{value = Value}]) ->
    Value.

xml_to_author(AuthorElement) ->
    [Author] = xpath("/author/name/text()", AuthorElement),
    #{name => Author#xmlText.value}.

xml_to_hash(HashElement) ->
    [#xmlAttribute{value = Alg}] = xpath("/hash/@alg", HashElement),
    [#xmlText{value = Hash}] = xpath("/hash/text()", HashElement),
    #{alg => Alg, hash => Hash}.

xml_to_external_reference(ExternalReferenceElement) ->
    [#xmlAttribute{value = Type}] = xpath("/reference/@type", ExternalReferenceElement),
    [#xmlText{value = Url}] = xpath("/reference/url/text()", ExternalReferenceElement),
    #external_reference{type = Type, url = Url}.

xml_to_license(LicenseElement) ->
    case xpath("/license/id/text()", LicenseElement) of
        [Value] ->
            #{id => Value#xmlText.value};
        [] ->
            [Value] = xpath("/license/name/text()", LicenseElement),
            #{name => Value#xmlText.value}
    end.

xpath(String, Xml) ->
    xmerl_xpath:string(String, Xml).
