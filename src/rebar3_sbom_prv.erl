%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2022 Bram Verburg
%% SPDX-FileCopyrightText: 2022 lafirest
%% SPDX-FileCopyrightText: 2024 Sebastian Strollo
%% SPDX-FileCopyrightText: 2024 Paulo F. Oliveira
%% SPDX-FileCopyrightText: 2024 Stritzinger GmbH

-module(rebar3_sbom_prv).

-export([init/1, do/1, format_error/1]).

-include("rebar3_sbom.hrl").

-moduledoc """
Rebar3 provider that implements the `rebar3 sbom` command (generates a CycloneDX SBoM).

Builds a CycloneDX SBoM from project and dependency metadata
(via `rebar3_sbom_cyclonedx:bom/5`), then encodes it with `m:rebar3_sbom_xml`
or `m:rebar3_sbom_json` and writes to the path given by `--output`
(default `./bom.xml` or `./bom.json`). PURL and CPE for components come from
`m:rebar3_sbom_purl` and `m:rebar3_sbom_cpe`; license IDs from
`m:rebar3_sbom_license`.
""".

%--- Macros --------------------------------------------------------------------
-define(CUSTOM_MAPPING, #{
    "github" => "vcs",
    "homepage" => "website",
    "releases" => "release-notes",
    "changelog" => "release-notes",
    "issues" => "issue-tracker"
}).

%% ===================================================================
%% Public API
%% ===================================================================
-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([
        % The 'user friendly' name of the task
        {name, ?PROVIDER},
        % The module implementation of the task
        {module, ?MODULE},
        % The task can be run by the user, always true
        {bare, true},
        % The list of dependencies
        {deps, ?DEPS},
        % How to use the plugin
        {example, "rebar3 sbom"},
        % list of options understood by the plugin
        {opts, [
            {format, $F, "format", {string, "xml"}, "file format, [xml|json]"},
            {output, $o, "output", {string, ?DEFAULT_OUTPUT},
                "the full path to the SBoM output file"},
            {force, $f, "force", {boolean, false},
                "overwite existing files without prompting for confirmation"},
            {strict_version, $V, "strict_version", {boolean, true},
                "modify the version number of the BoM only when the content changes"},
            {author, $a, "author", string, "the author of the SBoM"}
        ]},
        {short_desc, "Generates CycloneDX SBoM"},
        {desc, "Generates a Software Bill-of-Materials (SBoM) in CycloneDX format"}
    ]),
    {ok, rebar_state:add_provider(State, Provider)}.

-doc """
Builds the SBoM via `rebar3_sbom_cyclonedx:bom/5`, encodes it (XML or JSON),
and writes the output file (see `m:rebar3_sbom_xml` or `m:rebar3_sbom_json`).
""".
-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    Format = proplists:get_value(format, Args),
    Output = proplists:get_value(output, Args),
    Force = proplists:get_value(force, Args),
    IsStrictVersion = proplists:get_value(strict_version, Args),
    [App0 | _] = rebar_state:project_apps(State),
    App = rebar_app_info:source(App0, root_app),
    PluginDeps = rebar_state:all_plugin_deps(State),
    {value, Plugin} = lists:search(
        fun(Plugin) ->
            rebar_app_info:name(Plugin) =:= <<"rebar3_sbom">>
        end,
        PluginDeps
    ),
    PluginInfo = dep_info(Plugin),
    PluginDepsInfo = [dep_info(Dep) || Dep <- PluginDeps],

    FilePath = filepath(Output, Format),
    DepsInfo = [dep_info(Dep) || Dep <- rebar_state:all_deps(State)],
    AppInfo = dep_info(App),
    AppInfo2 = [{sha256, hash(AppInfo, rebar_dir:base_dir(State))} | AppInfo],
    MetadataInfo = metadata(State),
    SBoM = rebar3_sbom_cyclonedx:bom(
        {FilePath, Format},
        IsStrictVersion,
        {AppInfo2, DepsInfo},
        {PluginInfo, PluginDepsInfo},
        MetadataInfo
    ),
    Contents =
        case Format of
            "xml" -> rebar3_sbom_xml:encode(SBoM);
            "json" -> rebar3_sbom_json:encode(SBoM)
        end,
    case write_file(FilePath, Contents, Force) of
        ok ->
            rebar_api:info("CycloneDX SBoM written to ~s", [FilePath]),
            {ok, State};
        {error, Message} ->
            {error, {?MODULE, Message}}
    end.

-doc "Formats provider errors for display to the user.".
-spec format_error(any()) -> iolist().
format_error(Message) ->
    io_lib:format("~s", [Message]).

-spec metadata(rebar_state:t()) -> proplists:proplist().
metadata(State) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    PluginOpts = rebar_state:get(State, rebar3_sbom, []),
    Manufacturer = proplists:get_value(sbom_manufacturer, PluginOpts, undefined),
    Licenses = proplists:get_value(sbom_licenses, PluginOpts, undefined),
    [
        {author, proplists:get_value(author, Args, undefined)},
        {manufacturer, Manufacturer},
        {licenses, Licenses}
    ].

dep_info(Dep) ->
    HexMetadata = hex_metadata(Dep),
    Name = rebar_app_info:name(Dep),
    Version = rebar_app_info:original_vsn(Dep),
    Source = rebar_app_info:source(Dep),
    Details = rebar_app_info:app_details(Dep),
    Deps = rebar_app_info:deps(Dep),
    Licenses0 = proplists:get_value(licenses, Details, []),
    HexMetadataLicenses = hex_metadata_licenses(HexMetadata),
    ExternalReferences =
        case proplists:get_value(links, Details) of
            undefined ->
                undefined;
            ExternalLinks ->
                find_references(ExternalLinks)
        end,
    % remove duplicates, if any
    Licenses = lists:usort(Licenses0 ++ HexMetadataLicenses),
    Links = proplists:get_value(links, Details, []),
    GitHubLink = get_github_link(HexMetadata, Links),
    Common =
        [
            {authors, proplists:get_value(maintainers, Details, [])},
            {description, proplists:get_value(description, Details)},
            {licenses, Licenses},
            {external_references, ExternalReferences},
            {dependencies, Deps},
            {scope, required},
            {github_link, GitHubLink}
        ],
    dep_info(Name, Version, Source, Common).

hex_metadata(Dep) ->
    DepDir = rebar_app_info:dir(Dep),
    % hardcoded in rebar3, too
    HexMetadataFile = "hex_metadata.config",
    HexMetadataPath = filename:join(DepDir, HexMetadataFile),

    case filelib:is_regular(HexMetadataPath) of
        true ->
            {ok, Terms} = file:consult(HexMetadataPath),
            Terms;
        false ->
            []
    end.

hex_metadata_licenses(HexMetadata) ->
    HexMetadataLicenses = proplists:get_value(<<"licenses">>, HexMetadata, []),
    [binary_to_list(HexMetadataLicense) || HexMetadataLicense <- HexMetadataLicenses].

-spec get_github_link(HexMetadata, Links) -> binary() when
    HexMetadata :: [{binary(), binary()}],
    Links :: [{string(), string()}].
get_github_link([], Links) ->
    case proplists:get_value("GitHub", Links, undefined) of
        undefined ->
            undefined;
        Value ->
            list_to_binary(Value)
    end;
get_github_link(HexMetadata, _) ->
    Links = proplists:get_value(<<"links">>, HexMetadata, []),
    proplists:get_value(<<"GitHub">>, Links, undefined).

find_references(Links) ->
    lists:foldl(
        fun({Type, Url}, Acc) ->
            LowerType = string:to_lower(Type),
            case maps:get(LowerType, ?CUSTOM_MAPPING, undefined) of
                undefined ->
                    case lists:member(LowerType, valid_external_reference_types()) of
                        true ->
                            Acc#{LowerType => Url};
                        false ->
                            Acc
                    end;
                _ when
                    LowerType =:= "changelog" andalso
                        is_map_key("release-note", Acc)
                ->
                    % changelog is a fallback for release-note.
                    % We don't overwrite the release-note if it already exists.
                    Acc;
                MappedType ->
                    Acc#{MappedType => Url}
            end
        end,
        #{},
        Links
    ).

valid_external_reference_types() ->
    % https://cyclonedx.org/docs/1.6/json/#metadata_component_externalReferences_items_type
    [
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
    ].

dep_info(_Name, _Version, {pkg, Name, Version, Sha256}, Common) ->
    GitHubLink = proplists:get_value(github_link, Common, undefined),
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(Sha256)},
        {cpe, rebar3_sbom_cpe:cpe(Name, list_to_binary(Version), GitHubLink)}
        | Common
    ];
dep_info(_Name, _Version, {pkg, Name, Version, _InnerChecksum, OuterChecksum, _RepoConf}, Common) ->
    GitHubLink = proplists:get_value(github_link, Common, undefined),
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(OuterChecksum)},
        {cpe, rebar3_sbom_cpe:cpe(Name, Version, GitHubLink)}
        | Common
    ];
dep_info(Name, _DepVersion, {git, Git, GitRef}, Common) ->
    {Version, Purl, CPE} =
        case GitRef of
            {tag, Tag} ->
                GeneratedCPE = rebar3_sbom_cpe:cpe(Name, list_to_binary(Tag), list_to_binary(Git)),
                {Tag, rebar3_sbom_purl:git(Name, Git, Tag), GeneratedCPE};
            {branch, Branch} ->
                GeneratedCPE = rebar3_sbom_cpe:cpe(
                    Name, list_to_binary(Branch), list_to_binary(Git)
                ),
                {Branch, rebar3_sbom_purl:git(Name, Git, Branch), GeneratedCPE};
            {ref, Ref} ->
                GeneratedCPE = rebar3_sbom_cpe:cpe(Name, list_to_binary(Ref), list_to_binary(Git)),
                {Ref, rebar3_sbom_purl:git(Name, Git, Ref), GeneratedCPE}
        end,
    [
        {name, Name},
        {version, Version},
        {purl, Purl},
        {cpe, CPE}
        | maybe_update_licenses(Purl, Common)
    ];
dep_info(Name, Version, {git_subdir, Git, Ref, _Dir}, Common) ->
    dep_info(Name, Version, {git, Git, Ref}, Common);
dep_info(Name, Version, checkout, Common) ->
    GitHubLink = proplists:get_value(github_link, Common, undefined),
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:local_otp_app(Name, Version)},
        {cpe, rebar3_sbom_cpe:cpe(Name, list_to_binary(Version), GitHubLink)}
        | Common
    ];
dep_info(Name, Version, root_app, Common) ->
    GitHubLink = proplists:get_value(github_link, Common, undefined),
    Purl = rebar3_sbom_purl:hex(Name, Version),
    [
        {name, Name},
        {version, Version},
        {purl, Purl},
        {cpe, rebar3_sbom_cpe:cpe(Name, list_to_binary(Version), GitHubLink)}
        | Common
    ].

filepath(?DEFAULT_OUTPUT, Format) ->
    "./bom." ++ Format;
filepath(Path, _Format) ->
    Path.

write_file(Filename, Contents, true) ->
    file:write_file(Filename, Contents);
write_file(Filename, Xml, false) ->
    case file:read_file_info(Filename) of
        {error, enoent} ->
            write_file(Filename, Xml, true);
        {ok, _FileInfo} ->
            Prompt = io_lib:format("File ~s exists; overwrite? [Y/N] ", [Filename]),
            case io:get_line(Prompt) of
                "y\n" -> write_file(Filename, Xml, true);
                "Y\n" -> write_file(Filename, Xml, true);
                _ -> {error, "Aborted"}
            end;
        Error ->
            Error
    end.

maybe_update_licenses(Purl, Common) ->
    case proplists:get_value(licenses, Common) of
        [_ | _] ->
            %% Non-empty list, ok
            Common;
        _ ->
            %% [] or 'undefined'
            case Purl of
                <<"pkg:github/", GithubPurlString/binary>> ->
                    case get_github_license(GithubPurlString) of
                        {ok, SPDX_Id} ->
                            lists:keyreplace(
                                licenses,
                                1,
                                Common,
                                {licenses, [SPDX_Id]}
                            );
                        _ ->
                            Common
                    end;
                _ ->
                    Common
            end
    end.

get_github_license(String) ->
    case re:split(String, <<"[/@]">>) of
        [Org, Repo, _Ref] ->
            get_github_license(Org, Repo);
        _ ->
            {error, string}
    end.

get_github_license(Org, Repo) ->
    URI =
        #{
            scheme => <<"https">>,
            path => filename:join([<<"/repos">>, Org, Repo, <<"license">>]),
            host => <<"api.github.com">>
        },
    URIStr = uri_string:recompose(URI),
    Headers = #{<<"user-agent">> => <<"rebar3">>},
    case rebar_httpc_adapter:request(get, URIStr, Headers, undefined, #{}) of
        {ok, {200, _ReplyHeaders, Body}} ->
            case jsone:decode(Body) of
                #{<<"license">> := #{<<"spdx_id">> := SPDX_Id}} ->
                    {ok, SPDX_Id};
                _ ->
                    {error, body}
            end;
        _ ->
            {error, request}
    end.

hash(AppInfo, BaseDir) ->
    Name = proplists:get_value(name, AppInfo),
    Version = proplists:get_value(version, AppInfo),
    TarPath = tar_path(BaseDir, Name, Version),
    case filelib:is_regular(TarPath) of
        true ->
            {ok, Content} = file:read_file(TarPath),
            Hash = crypto:hash(sha256, Content),
            iolist_to_binary([io_lib:format("~2.16.0b", [X]) || <<X>> <= Hash]);
        false ->
            rebar_api:warn(
                "Could not compute hash. Tarball not found: ~p",
                [TarPath]
            ),
            undefined
    end.

tar_path(BaseDir, Name, Version) ->
    TarFilename = io_lib:format("~s-~s.tar.gz", [Name, Version]),
    filename:join([BaseDir, "rel", Name, TarFilename]).
