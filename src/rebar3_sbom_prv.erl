%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2022 Bram Verburg
%% SPDX-FileCopyrightText: 2022 lafirest
%% SPDX-FileCopyrightText: 2024 Sebastian Strollo
%% SPDX-FileCopyrightText: 2024 Paulo F. Oliveira
%% SPDX-FileCopyrightText: 2024 Stritzinger GmbH

-module(rebar3_sbom_prv).

-export([init/1, do/1, format_error/1]).

-include("rebar3_sbom.hrl").

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

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    %% Create a httpc profile using proxy settings from the environment, if any
    {ok, _Started} = application:ensure_all_started(inets),
    {ok, _Pid} = inets:start(httpc, [{profile, rebar3_sbom}]),
    ok = set_httpc_proxy(rebar3_sbom),

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

    inets:stop(httpc, rebar3_sbom),

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
    BaseHeaders = #{<<"user-agent">> => <<"rebar3">>},
    Headers =
        case os:getenv("GITHUB_TOKEN") of
            false -> BaseHeaders;
            Token -> BaseHeaders#{<<"authorization">> => iolist_to_binary(["Bearer ", Token])}
        end,
    case rebar_httpc_adapter:request(get, URIStr, Headers, undefined, #{profile => rebar3_sbom}) of
        {ok, {200, _ReplyHeaders, Body}} ->
            case jsone:decode(Body) of
                #{<<"license">> := #{<<"spdx_id">> := SPDX_Id}} ->
                    {ok, SPDX_Id};
                _ ->
                    {error, body}
            end;
        {ok, {404, _ReplyHeaders, _Body}} ->
            rebar_api:error(
                "Fetching license info from github failed, maybe the repository doesn't exist,~n"
                "isn't accessible, or license info is missing in the repository.~nRepository: ~p~n",
                [URIStr]
            ),
            {error, request};
        _Other ->
            rebar_api:error("Fetching license info from github failed.~nRepository: ~p~n", [URIStr]),
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

set_httpc_proxy(Profile) ->
    HttpProxy = get_proxy("http_proxy"),
    HttpsProxy = get_proxy("https_proxy"),
    NoProxy = get_no_proxy(),
    Options =
        format_option(proxy, HttpProxy, NoProxy) ++
            format_option(https_proxy, HttpsProxy, NoProxy),
    case Options of
        [] ->
            ok;
        Opts ->
            httpc:set_options(Opts, Profile)
    end.

format_option(_Option, undefined, _NoProxy) ->
    [];
format_option(Option, Url, NoProxy) ->
    case uri_string:parse(Url) of
        #{host := Host, port := Port} ->
            [{Option, {{Host, Port}, NoProxy}}];
        #{host := Host} ->
            [{Option, {{Host, 8080}, NoProxy}}];
        _Other ->
            rebar_api:error("Invalid proxy URL ~s for ~s~n", [Url, Option]),
            []
    end.

get_proxy(ProxyString) ->
    case os:getenv(string:lowercase(ProxyString)) of
        false ->
            case os:getenv(string:uppercase(ProxyString)) of
                false ->
                    undefined;
                Url ->
                    Url
            end;
        Url ->
            Url
    end.

get_no_proxy() ->
    case os:getenv("no_proxy") of
        false ->
            case os:getenv("NO_PROXY") of
                false ->
                    ["localhost", "127.0.0.1"];
                NP ->
                    parse_no_proxy(NP)
            end;
        NP ->
            parse_no_proxy(NP)
    end.

%% Splits comma-separated values and formats them for httpc
parse_no_proxy(NPString) ->
    RawTokens = string:lexemes(NPString, ","),
    lists:map(fun(Token) -> format_entry(string:trim(Token)) end, RawTokens).

%% Translate standard .domain to httpc *.domain format
format_entry([$. | Domain]) -> "*." ++ Domain;
%% Keep regular hostnames and raw IPs unchanged
format_entry(Other) -> Other.
