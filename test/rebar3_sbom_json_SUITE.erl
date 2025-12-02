-module(rebar3_sbom_json_SUITE).

% CT Exports
-export([all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).

% Testcases
-export([required_fields_test/1]).
-export([serial_number_test/1]).
-export([version_test/1]).
-export([github_actor_test/1]).
-export([default_author_test/1]).
-export([empty_manufacturer_url_test/1]).
-export([manufacturer_empty_url_array_test/1]).
-export([metadata_component_hashes_test/1]).

% metadata group test cases
-export([timestamp_test/1]).
-export([tools_test/1]).
-export([metadata_authors_test/1]).
-export([licenses_test/1]).
-export([component_test/1]).
-export([manufacturer_test/1]).

% components group test cases
-export([required_component_fields_test/1]).
-export([all_deps_present_test/1]).
-export([scope_test/1]).
-export([component_hashes_test/1]).
-export([component_licenses_test/1]).
-export([component_purl_test/1]).
-export([component_cpe_test/1]).
-export([component_external_references_test/1]).

% basic app with SBoM group test cases
-export([serial_number_change_test/1]).
-export([version_increment_test/1]).
-export([timestamp_increases_test/1]).

% local app group test cases
-export([no_sbom_manufacturer_test/1]).
-export([no_sbom_licenses_test/1]).
-export([metadata_component_empty_links_cpe_test/1]).
-export([external_references_fallback_test/1]).
-export([checkout_app_dependency_test/1]).

% Includes
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("rebar3_sbom/include/rebar3_sbom.hrl").

% Macros
-define(SERIAL_NB_REGEX, "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").
-define(RFC3339_REGEX,
    "^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])[T\\s]([01]\\d|2[0-3]):([0-5]\\d):([0-5]\\d)(\\.\\d+)?(Z|[+-]([01]\\d|2[0-3]):[0-5]\\d)$"
).
-define(BOM_LINK_INTRO, "urn:cdx").
-define(VALID_HASH_ALGORITHMS, [
    <<"MD5">>,
    <<"SHA-1">>,
    <<"SHA-256">>,
    <<"SHA-384">>,
    <<"SHA-512">>,
    <<"SHA3-256">>,
    <<"SHA3-384">>,
    <<"SHA3-512">>,
    <<"BLAKE2b-256">>,
    <<"BLAKE2b-384">>,
    <<"BLAKE2b-512">>,
    <<"BLAKE3">>,
    <<"Streebog-256">>,
    <<"Streebog-512">>
]).
-define(HASH_CONTENT_REGEX,
    "^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$"
).
-define(PURL_REGEX, "^pkg:[a-z][a-z0-9+.-]*/([^/@?#]+/)*[^/@?#]+(@[^?#]+)?(\\?[^#]+)?(#.+)?$").
-define(TAR_REL_PATH, "/_build/default/rel/basic_app/basic_app-0.1.0.tar.gz").
% Reference: https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
-define(CPE_REGEX,
    "^cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){4}$"
).
-define(VALID_EXTERNAL_REFERENCE_TYPES, [
    "vcs",
    "issue-tracker",
    "website",
    "advisories",
    "bom",
    "mailing-list",
    "social",
    "chat",
    "documentation",
    "support",
    "source-distribution",
    "distribution",
    "distribution-intake",
    "license",
    "build-meta",
    "build-system",
    "release-notes",
    "security-contact",
    "model-card",
    "log",
    "configuration",
    "evidence",
    "formulation",
    "attestation",
    "threat-model",
    "adversary-model",
    "risk-assessment",
    "vulnerability-assertion",
    "exploitability-statement",
    "pentest-report",
    "static-analysis-report",
    "dynamic-analysis-report",
    "runtime-analysis-report",
    "component-analysis-report",
    "maturity-report",
    "certification-report",
    "codified-infrastructure",
    "quality-metrics",
    "poam",
    "electronic-signature",
    "digital-signature",
    "rfc-9116",
    "patent",
    "patent-family",
    "patent-assertion",
    "citation",
    "other"
]).

-define(BASIC_APP_SBOM, "basic_app_sbom.json").
-define(LOCAL_APP_SBOM, "local_app_sbom.json").
%--- Common test functions -----------------------------------------------------

all() ->
    [
        {group, basic_app},
        {group, local_app}
    ].

groups() ->
    [
        {basic_app, [], [
            required_fields_test,
            serial_number_test,
            version_test,
            {group, metadata},
            {group, components},
            {group, basic_app_with_sbom},
            github_actor_test,
            default_author_test,
            empty_manufacturer_url_test,
            metadata_component_hashes_test
        ]},
        {metadata, [], [
            timestamp_test,
            % tools_test,
            metadata_authors_test,
            % TODO validate the license.id using CycloneDX list of valid SPDX license ID
            licenses_test,
            component_test,
            manufacturer_test
        ]},
        {components, [], [
            required_component_fields_test,
            all_deps_present_test,
            scope_test,
            component_hashes_test,
            component_licenses_test,
            component_purl_test,
            component_cpe_test,
            component_external_references_test
        ]},
        {basic_app_with_sbom, [], [
            serial_number_change_test,
            version_increment_test,
            timestamp_increases_test
        ]},
        {local_app, [], [
            no_sbom_manufacturer_test,
            no_sbom_licenses_test,
            metadata_component_empty_links_cpe_test,
            external_references_fallback_test,
            checkout_app_dependency_test
        ]}
    ].

init_per_suite(Config) ->
    application:load(rebar3_sbom),
    {ok, PluginVersion} = application:get_key(rebar3_sbom, vsn),
    {ok, PluginDescription} = application:get_key(rebar3_sbom, description),
    [
        {plugin_version, list_to_binary(PluginVersion)},
        {plugin_description, list_to_binary(PluginDescription)}
        | Config
    ].

end_per_suite(_Config) ->
    ok.

init_per_group(basic_app, Config) ->
    State = init_rebar_state(Config, "basic_app"),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, ?BASIC_APP_SBOM),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-a", "Jane Doe"],
    {ok, FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    SBoMJSON = json:decode(File),
    AllDeps = lists:map(
        fun(Dep) -> atom_to_binary(Dep) end,
        rebar_state:get(FinalState, deps)
    ),
    [
        {sbom_path, SBoMPath},
        {sbom_json, SBoMJSON},
        {all_deps, AllDeps}
        | Config
    ];
init_per_group(basic_app_with_sbom, Config) ->
    % makes sure that new generated TS must be different
    timer:sleep(1000),
    State = init_rebar_state(Config, "basic_app"),
    SBoMPath = ?config(sbom_path, Config),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{new_sbom_json, NewSBoMJSON} | Config];
init_per_group(metadata, Config) ->
    #{<<"metadata">> := Metadata} = ?config(sbom_json, Config),
    [{metadata, Metadata} | Config];
init_per_group(local_app, Config) ->
    State = init_rebar_state(Config, "local_app"),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, ?LOCAL_APP_SBOM),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{sbom_json, NewSBoMJSON} | Config];
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(github_actor_test, Config) ->
    os:putenv("GITHUB_ACTOR", "Bilbo Baggins"),
    State = init_rebar_state(Config, "basic_app"),
    SBoMPath = ?config(sbom_path, Config),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{sbom_json, NewSBoMJSON} | Config];
init_per_testcase(default_author_test, Config) ->
    State = init_rebar_state(Config, "basic_app"),
    SBoMPath = ?config(sbom_path, Config),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{sbom_json, NewSBoMJSON} | Config];
init_per_testcase(empty_manufacturer_url_test, Config) ->
    State = init_rebar_state(Config, "basic_app"),
    PluginOpts = rebar_state:get(State, rebar3_sbom),
    Manufacturer = proplists:get_value(sbom_manufacturer, PluginOpts),
    NewPluginOpts = lists:keyreplace(
        sbom_manufacturer,
        1,
        PluginOpts,
        {sbom_manufacturer, maps:remove(url, Manufacturer)}
    ),
    State2 = rebar_state:set(State, rebar3_sbom, NewPluginOpts),
    SBoMPath = ?config(sbom_path, Config),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State2, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{sbom_json, NewSBoMJSON} | Config];
init_per_testcase(manufacturer_empty_url_array_test, Config) ->
    State = init_rebar_state(Config, "basic_app"),
    PluginOpts = rebar_state:get(State, rebar3_sbom),
    Manufacturer = proplists:get_value(sbom_manufacturer, PluginOpts),
    NewPluginOpts = lists:keyreplace(
        sbom_manufacturer,
        1,
        PluginOpts,
        {sbom_manufacturer, Manufacturer#{url => []}}
    ),
    State2 = rebar_state:set(State, rebar3_sbom, NewPluginOpts),
    SBoMPath = ?config(sbom_path, Config),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State2, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{sbom_json, NewSBoMJSON} | Config];
init_per_testcase(metadata_component_hashes_test, Config) ->
    State = init_rebar_state(Config, "basic_app"),
    SBoMPath = ?config(sbom_path, Config),
    {ok, _} = rebar3:run(State, ["tar"]),
    ExpectedHash = get_tar_hash(?config(priv_dir, Config)),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{sbom_json, NewSBoMJSON}, {expected_hash, ExpectedHash} | Config];
init_per_testcase(_, Config) ->
    Config.

end_per_testcase(github_actor_test, _) ->
    os:unsetenv("GITHUB_ACTOR");
end_per_testcase(_, _Config) ->
    ok.

%--- Tests ---------------------------------------------------------------------

%--- basic_app group ---
required_fields_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"bomFormat">> := BomFormat, <<"specVersion">> := SpecVersion} = SBoMJSON,
    ?assertEqual(<<"CycloneDX">>, BomFormat),
    ?assertEqual(<<?SPEC_VERSION/bitstring>>, SpecVersion).

serial_number_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"serialNumber">> := SerialNumber} = SBoMJSON,
    ?assertNotEqual(nomatch, re:run(SerialNumber, ?SERIAL_NB_REGEX)).

version_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"version">> := Version} = SBoMJSON,
    % Since the app doesn't have a SBoM version should be 1
    ?assertEqual(1, Version).

github_actor_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := Metadata} = SBoMJSON,
    #{<<"authors">> := Authors} = Metadata,
    ?assertMatch([#{<<"name">> := <<"Bilbo Baggins">>}], Authors).

default_author_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := Metadata} = SBoMJSON,
    #{<<"authors">> := Authors} = Metadata,
    ?assertMatch([#{<<"name">> := <<"John Doe">>}], Authors).

empty_manufacturer_url_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := #{<<"manufacturer">> := Manufacturer}} = SBoMJSON,
    ?assertNotMatch(#{<<"url">> := _}, Manufacturer).

manufacturer_empty_url_array_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := #{<<"manufacturer">> := Manufacturer}} = SBoMJSON,
    ?assertNotMatch(#{<<"url">> := _}, Manufacturer).

metadata_component_hashes_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    ExpectedHash = ?config(expected_hash, Config),
    #{<<"metadata">> := #{<<"component">> := Component}} = SBoMJSON,
    #{<<"hashes">> := Hashes} = Component,
    check_hashes_constraints(Hashes),
    [Hash] = Hashes,
    ?assertMatch(
        #{
            <<"alg">> := <<"SHA-256">>,
            <<"content">> := ExpectedHash
        },
        Hash
    ).

%--- metadata group ---
timestamp_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := Metadata} = SBoMJSON,
    #{<<"timestamp">> := Timestamp} = Metadata,
    ?assertNotEqual(nomatch, re:run(Timestamp, ?RFC3339_REGEX)),
    % Make sure that TS is different
    timer:sleep(1000),
    SysTimeNow = erlang:system_time(second),
    StringTS = binary_to_list(Timestamp),
    TsSysTime = calendar:rfc3339_to_system_time(StringTS),
    ?assert(TsSysTime < SysTimeNow).

tools_test(Config) ->
    % Assume that in basic_app we only have a component for rebar3_sbom
    #{<<"tools">> := Tools} = ?config(metadata, Config),
    ?assertMatch([_], Tools),
    [Tool] = Tools,
    check_component_constraints(Tool),
    #{
        <<"type">> := Type,
        <<"name">> := Name,
        <<"isExternal">> := IsExternal,
        <<"version">> := Version,
        <<"description">> := Description,
        <<"hashes">> := Hashes,
        <<"purl">> := Purl,
        <<"licenses">> := [License]
    } = Tool,
    ?assertEqual(<<"application">>, Type),
    ?assertEqual(<<"rebar3_sbom">>, Name),
    ?assertNot(IsExternal),
    check_bom_ref_format(Tool),
    ?assertEqual(?config(plugin_version, Config), Version),
    ?assertEqual(?config(plugin_description, Config), Description),
    % TODO Test if hashes values are correct
    check_hashes_constraints(Hashes),
    check_purl_format(Purl),
    ?assertMatch(<<"pkg:hex/rebar3_sbom", _/bitstring>>, Purl),
    ?assertMatch(#{<<"license">> := #{<<"id">> := <<"Apache-2.0">>}}, License).

metadata_authors_test(Config) ->
    #{<<"authors">> := Authors} = ?config(metadata, Config),
    ?assertMatch([_], Authors),
    [Author] = Authors,
    ?assertMatch(#{<<"name">> := <<"Jane Doe">>}, Author).

licenses_test(Config) ->
    Metadata = ?config(metadata, Config),
    ?assertMatch(
        #{<<"licenses">> := [_]},
        Metadata,
        "metadata.licenses is missing"
    ),
    #{<<"licenses">> := [License]} = Metadata,
    ?assertMatch(#{<<"license">> := #{<<"id">> := <<"BSD-3-Clause">>}}, License).

component_test(Config) ->
    #{<<"component">> := Component} = ?config(metadata, Config),
    check_component_constraints(Component),
    #{
        <<"type">> := Type,
        <<"name">> := Name,
        <<"version">> := Version,
        <<"description">> := Description,
        <<"licenses">> := [License],
        <<"purl">> := Purl,
        <<"hashes">> := Hashes
    } = Component,
    ?assertEqual(<<"application">>, Type, "metadata.component.type"),
    ?assertEqual(<<"basic_app">>, Name, "metadata.component.name"),
    ?assertEqual(<<"0.1.0">>, Version, "metadata.component.version"),
    ?assertEqual(
        <<"Basic app for testing rebar3_sbom">>,
        Description,
        "metadata.component.description"
    ),
    % Hashes are empty because we don't have a tarball to compute it
    ?assertEqual([], Hashes, "metadata.component.hashes"),
    ?assertMatch(
        #{<<"license">> := #{<<"id">> := <<"Apache-2.0">>}},
        License,
        "metadata.component.licenses[0].license.id"
    ),
    check_purl_format(Purl),
    ?assertEqual(
        <<"pkg:hex/basic_app@0.1.0">>,
        Purl,
        "metadata.component.purl"
    ),
    ?assertMatch(
        #{<<"cpe">> := _},
        Component,
        "metadata.component.cpe is missing"
    ),
    #{<<"cpe">> := Cpe} = Component,
    ?assertEqual(<<"cpe:2.3:a:example-org:basic_app:0.1.0:*:*:*:*:*:*:*">>, Cpe),
    ?assertMatch(#{<<"externalReferences">> := [_ | _]}, Component),
    #{<<"externalReferences">> := ExternalReferences} = Component,
    check_external_references_constraints(ExternalReferences),
    ExpectedExternalReferences = [
        #{<<"type">> => <<"vcs">>, <<"url">> => <<"https://github.com/example-org/basic_app">>},
        #{<<"type">> => <<"website">>, <<"url">> => <<"https://example.com">>},
        #{<<"type">> => <<"release-notes">>, <<"url">> => <<"https://example.com/releases">>},
        #{<<"type">> => <<"issue-tracker">>, <<"url">> => <<"https://example.com/issues">>},
        #{<<"type">> => <<"documentation">>, <<"url">> => <<"https://example.com/documentation">>}
    ],
    lists:foreach(
        fun(ExpectedExternalReference) ->
            ?assert(
                lists:member(ExpectedExternalReference, ExternalReferences),
                ExpectedExternalReference
            )
        end,
        ExpectedExternalReferences
    ),
    ?assertEqual(5, length(ExternalReferences)).

manufacturer_test(Config) ->
    #{<<"manufacturer">> := Manufacturer} = ?config(metadata, Config),
    ?assertMatch(#{<<"name">> := <<"The comunity of the Ring">>}, Manufacturer),
    ?assertMatch(#{<<"address">> := _}, Manufacturer),
    #{<<"address">> := Address} = Manufacturer,
    ?assertMatch(
        #{
            <<"country">> := <<"Middle-earth">>,
            <<"region">> := <<"Shire">>,
            <<"locality">> := <<"Hobbiton">>,
            <<"postal_code">> := <<"12345">>,
            <<"street_address">> := <<"Bag End, Hobbiton, Shire">>
        },
        Address
    ),
    ?assertMatch(#{<<"contact">> := [_ | _]}, Manufacturer),
    #{<<"contact">> := [Contact1, Contact2]} = Manufacturer,
    ?assertEqual(#{<<"name">> => <<"Frodo Baggins">>}, Contact1),
    ?assertEqual(
        #{
            <<"name">> => <<"Gandalf the Grey">>,
            <<"phone">> => <<"1234567890">>
        },
        Contact2
    ),
    ?assertMatch(#{<<"url">> := [_ | _]}, Manufacturer),
    #{<<"url">> := [Url1, Url2]} = Manufacturer,
    ?assertEqual(<<"https://example.com">>, Url1),
    ?assertEqual(<<"https://another-example.com">>, Url2),
    ?assertNotMatch(#{<<"post_office_box_number">> := _}, Address),
    ?assertNotMatch(#{<<"bom-ref">> := _}, Manufacturer).

%--- components group ---
required_component_fields_test(Config) ->
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    lists:foreach(
        fun(Component) ->
            check_component_constraints(Component)
        end,
        Components
    ).

all_deps_present_test(Config) ->
    AllDeps = ?config(all_deps, Config),
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    AllComponentNames = lists:map(
        fun(Component) ->
            #{<<"name">> := Name} = Component,
            Name
        end,
        Components
    ),
    lists:foreach(
        fun(DeclaredDep) ->
            ?assert(
                lists:member(DeclaredDep, AllComponentNames),
                io_lib:format("Dependency ~s is missing from the SBoM", [DeclaredDep])
            )
        end,
        AllDeps
    ).

scope_test(Config) ->
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    lists:foreach(
        fun(Component) ->
            #{<<"scope">> := Scope} = Component,
            ?assertEqual(<<"required">>, Scope)
        end,
        Components
    ).

component_hashes_test(Config) ->
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    lists:foreach(
        fun(Component) ->
            #{<<"hashes">> := Hashes} = Component,
            check_hashes_constraints(Hashes)
        end,
        Components
    ).

component_licenses_test(Config) ->
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    lists:foreach(
        fun(Component) ->
            #{<<"licenses">> := Licenses} = Component,
            % All deps of basic_app have at least one license
            ?assertNotMatch([], Licenses),
            check_licenses_constraints(Licenses)
        end,
        Components
    ).

component_purl_test(Config) ->
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    lists:foreach(
        fun(Component) ->
            #{<<"name">> := Name, <<"version">> := Version, <<"purl">> := Purl} = Component,
            check_purl_format(Purl),
            ?assertEqual(<<"pkg:hex/", Name/bitstring, "@", Version/bitstring>>, Purl)
        end,
        Components
    ).

component_cpe_test(Config) ->
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    lists:foreach(fun check_cpe_content/1, Components).

component_external_references_test(Config) ->
    #{<<"components">> := Components} = ?config(sbom_json, Config),
    lists:foreach(
        fun(Component) ->
            #{<<"externalReferences">> := ExternalReferences} = Component,
            check_external_references_constraints(ExternalReferences)
        % TODO: check content ? Need to discuss about this
        % We don't control the content of the deps
        % A change in the content of the deps should not break the test
        end,
        Components
    ).

%--- basic_app_with_sbom group ---
serial_number_change_test(Config) ->
    OldSBoMJSON = ?config(sbom_json, Config),
    NewSBoMJSON = ?config(new_sbom_json, Config),
    #{<<"serialNumber">> := OldSerialNumber} = OldSBoMJSON,
    #{<<"serialNumber">> := NewSerialNumber} = NewSBoMJSON,
    ?assertNotEqual(nomatch, re:run(NewSerialNumber, ?SERIAL_NB_REGEX)),
    ?assertNotEqual(OldSerialNumber, NewSerialNumber).

version_increment_test(Config) ->
    OldSBoMJSON = ?config(sbom_json, Config),
    NewSBoMJSON = ?config(new_sbom_json, Config),
    #{<<"version">> := OldVersion} = OldSBoMJSON,
    #{<<"version">> := NewVersion} = NewSBoMJSON,
    ?assertNotEqual(OldVersion, NewVersion),
    ?assert(NewVersion > OldVersion andalso NewVersion > 1).

timestamp_increases_test(Config) ->
    #{<<"metadata">> := OldMetaData} = ?config(sbom_json, Config),
    #{<<"timestamp">> := OldTs} = OldMetaData,
    #{<<"metadata">> := NewMetadata} = ?config(new_sbom_json, Config),
    #{<<"timestamp">> := NewTs} = NewMetadata,
    OldSysTime = calendar:rfc3339_to_system_time(binary_to_list(OldTs)),
    NewSysTime = calendar:rfc3339_to_system_time(binary_to_list(NewTs)),
    ?assert(OldSysTime < NewSysTime).

%--- local_app group ---
no_sbom_manufacturer_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := Metadata} = SBoMJSON,
    ?assertNotMatch(#{<<"manufacturer">> := _}, Metadata).

no_sbom_licenses_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    % Get component licenses and check if metadata.licences matches with them
    #{
        <<"metadata">> := #{
            <<"licenses">> := MetadataLicenses,
            <<"component">> := #{<<"licenses">> := ComponentLicenses}
        }
    } = SBoMJSON,
    ?assertMatch(ComponentLicenses, MetadataLicenses).

metadata_component_empty_links_cpe_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := #{<<"component">> := Component}} = SBoMJSON,
    ?assertNotMatch(#{<<"cpe">> := _}, Component).

external_references_fallback_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := #{<<"component">> := Component}} = SBoMJSON,
    #{<<"externalReferences">> := ExternalReferences} = Component,
    ?assertMatch(
        [#{<<"type">> := <<"release-notes">>, <<"url">> := <<"https://example.com/changelog">>}],
        ExternalReferences
    ).

checkout_app_dependency_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"components">> := Components} = SBoMJSON,
    Value = lists:search(
        fun(Component) ->
            maps:get(<<"name">>, Component, undefined) =:= <<"checkout_app">>
        end,
        Components
    ),
    ?assertMatch({value, _}, Value),
    {_, Dependency} = Value,
    check_component_constraints(Dependency),
    ?assertMatch(
        #{
            <<"version">> := <<"0.1.0">>,
            <<"name">> := <<"checkout_app">>,
            <<"purl">> := <<"pkg:otp/checkout_app@0.1.0">>,
            <<"licenses">> := _
        },
        Dependency
    ).

%--- Private -------------------------------------------------------------------
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
    BaseDir = filename:join([PrivDir, "_build"]),
    State = rebar_state:new([
        {base_dir, BaseDir},
        {root_dir, AppDir}
    ]),
    RebarConfig = rebar_config:consult(AppDir),
    State2 = rebar_state:new(State, RebarConfig, AppDir),
    {ok, NewState} = rebar3_sbom_prv:init(State2),
    NewState.

check_component_constraints(Component) ->
    check_component_cyclonedx_constraints(Component),
    check_component_ort_constraints(Component).

% These are the constraints defined by the CycloneDX JSON reference
check_component_cyclonedx_constraints(Component) ->
    case Component of
        #{<<"version">> := _, <<"versionRange">> := _} ->
            ct:fail(
                "Requirement 1: version and versionRange shall not be " ++
                    "present simultaneously."
            );
        #{<<"isExternal">> := false, <<"versionRange">> := _} ->
            ct:fail(
                "Requirement 2: versionRange must not be present when " ++
                    "isExternal is false."
            );
        #{<<"author">> := _} ->
            ct:fail("author field is deprecated");
        #{<<"modified">> := _} ->
            ct:fail("modified field is deprecated");
        #{<<"type">> := Type, <<"name">> := _} ->
            ?assert(
                Type =/= <<"data">> orelse maps:is_key(<<"data">>, Component),
                "If component.type is 'data', then component.data must be present"
            ),
            ok;
        _ ->
            ct:fail("Missing required field 'type' and/or 'name'")
    end.

% These are the constraints that we impose for ORT
check_component_ort_constraints(Component) ->
    ?assert(
        maps:is_key(<<"bom-ref">>, Component),
        "Component bom-ref is missing"
    ),
    #{<<"bom-ref">> := BomRef} = Component,
    ?assertMatch([_ | _], binary_to_list(BomRef)),
    ?assert(
        maps:is_key(<<"version">>, Component) orelse
            maps:is_key(<<"versionRange">>, Component),
        "Component version or version range is missing"
    ),
    ?assert(
        maps:is_key(<<"description">>, Component),
        "Component description is missing"
    ),
    ?assert(
        maps:is_key(<<"licenses">>, Component),
        "Component licenses are required"
    ),
    ?assert(
        maps:is_key(<<"purl">>, Component),
        "Component purl is missing"
    ),
    ?assert(
        maps:is_key(<<"scope">>, Component),
        "Component scope is missing"
    ),
    ?assert(
        maps:is_key(<<"hashes">>, Component),
        "Component hashes are missing"
    ).

check_bom_ref_format(Component) ->
    #{<<"bom-ref">> := BomRef} = Component,
    ?assertNotMatch(<<?BOM_LINK_INTRO, _/bitstring>>, BomRef).

check_hashes_constraints(Hashes) ->
    lists:foreach(
        fun
            (#{<<"alg">> := Alg, <<"content">> := Content}) ->
                ?assert(lists:member(Alg, ?VALID_HASH_ALGORITHMS)),
                ?assertNotEqual(nomatch, re:run(Content, ?HASH_CONTENT_REGEX));
            (_) ->
                ct:fail(
                    "The hash object doesn't have alg or/and" ++
                        "content"
                )
        end,
        Hashes
    ).

check_purl_format(Purl) ->
    ?assertNotEqual(nomatch, re:run(Purl, ?PURL_REGEX)).

check_licenses_constraints(Licenses) ->
    lists:foreach(
        fun(License) ->
            ?assertMatch(#{<<"license">> := #{<<"id">> := _}}, License)
        end,
        Licenses
    ).

get_tar_hash(PrivDir) ->
    {ok, Content} = file:read_file(PrivDir ++ ?TAR_REL_PATH),
    ComputedHash = crypto:hash(sha256, Content),
    iolist_to_binary([io_lib:format("~2.16.0b", [X]) || <<X>> <= ComputedHash]).

check_cpe_format(Cpe) ->
    ?assertNotEqual(nomatch, re:run(Cpe, ?CPE_REGEX)).

check_cpe_content(#{<<"name">> := <<"hex_core">>} = Component) ->
    #{<<"version">> := Version, <<"cpe">> := Cpe} = Component,
    check_cpe_format(Cpe),
    ?assertEqual(
        <<"cpe:", ?CPE_VERSION/bitstring, ":a:hex:hex_core:", Version/bitstring, ":*:*:*:*:*:*:*">>,
        Cpe
    );
check_cpe_content(#{<<"name">> := <<"grisp">>} = Component) ->
    #{<<"version">> := Version, <<"cpe">> := Cpe} = Component,
    check_cpe_format(Cpe),
    ?assertEqual(
        <<"cpe:", ?CPE_VERSION/bitstring, ":a:grisp:grisp:", Version/bitstring, ":*:*:*:*:*:*:*">>,
        Cpe
    );
check_cpe_content(#{<<"name">> := <<"meck">>} = Component) ->
    #{<<"version">> := Version, <<"cpe">> := Cpe} = Component,
    check_cpe_format(Cpe),
    ?assertEqual(
        <<"cpe:", ?CPE_VERSION/bitstring, ":a:eproxus:meck:", Version/bitstring, ":*:*:*:*:*:*:*">>,
        Cpe
    );
check_cpe_content(Component) ->
    #{
        <<"name">> := Name,
        <<"version">> := Version,
        <<"cpe">> := Cpe
    } = Component,
    check_cpe_format(Cpe),
    CpeList = string:tokens(binary_to_list(Cpe), ":"),
    [_, CpeVersion, Part, _, CpeProduct, CpeAppVersion | _] = CpeList,
    ?assertEqual(binary_to_list(?CPE_VERSION), CpeVersion),
    ?assertEqual("a", Part),
    ?assertEqual(binary_to_list(Name), CpeProduct),
    ?assertEqual(binary_to_list(Version), CpeAppVersion).

check_external_references_constraints(ExternalReferences) ->
    lists:foreach(
        fun(ExternalReference) ->
            % TODO check that the type is valid
            ?assertMatch(
                #{<<"type">> := _}, ExternalReference, "External reference type is missing"
            ),
            #{<<"type">> := Type} = ExternalReference,
            TypeString = binary_to_list(Type),
            ?assert(
                lists:member(TypeString, ?VALID_EXTERNAL_REFERENCE_TYPES),
                "External reference type '" ++ TypeString ++ "' is invalid"
            ),
            ?assertMatch(#{<<"url">> := _}, ExternalReference, "External reference url is missing")
        end,
        ExternalReferences
    ).
