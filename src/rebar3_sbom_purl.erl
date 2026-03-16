%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2020 Andrew Mayorov
%% SPDX-FileCopyrightText: 2022 Bram Verburg
%% SPDX-FileCopyrightText: 2024 Sebastian Strollo
%% SPDX-FileCopyrightText: 2025 Stritzinger GmbH

-module(rebar3_sbom_purl).

% https://github.com/package-url/purl-spec

-export([hex/2, git/3, github/2, bitbucket/2, local_otp_app/2, local/2, otp_runtime/2]).

hex(Name, Version) ->
    purl(["hex", string:lowercase(to_list(Name))], to_list(Version)).

git(_Name, Git0, Ref0) ->
    Git = to_list(Git0),
    Ref = to_list(Ref0),
    case Git of
        "git@github.com:" ++ Path ->
            github(string:replace(Path, ".git", "", trailing), Ref);
        "https://github.com/" ++ Path ->
            github(string:replace(Path, ".git", "", trailing), Ref);
        "git://github.com/" ++ Path ->
            github(string:replace(Path, ".git", "", trailing), Ref);
        "git@bitbucket.org:" ++ Path ->
            bitbucket(string:replace(Path, ".git", "", trailing), Ref);
        "https://bitbucket.org/" ++ Path ->
            bitbucket(string:replace(Path, ".git", "", trailing), Ref);
        "git://bitbucket.org/" ++ Path ->
            bitbucket(string:replace(Path, ".git", "", trailing), Ref);
        _ ->
            undefined
    end.

github(Repo, Ref) ->
    [Organization, Name | _] = string:split(Repo, "/"),
    purl(["github", string:lowercase(Organization), string:lowercase(Name)], Ref).

bitbucket(Repo, Ref) ->
    [Organization, Name | _] = string:split(Repo, "/"),
    purl(["bitbucket", string:lowercase(Organization), string:lowercase(Name)], Ref).

local_otp_app(Name, Version) ->
    purl(["otp", string:lowercase(to_list(Name))], to_list(Version)).

local(Name, Version) ->
    purl(["generic", string:lowercase(to_list(Name))], to_list(Version)).

otp_runtime(Name, Version) ->
    purl(["otp", string:lowercase(to_list(Name))], to_list(Version)).

purl(PathSegments, Version) ->
    Path = lists:join("/", [escape(Segment) || Segment <- PathSegments]),
    unicode:characters_to_binary(io_lib:format("pkg:~s@~s", [Path, escape(Version)])).

-if(?OTP_RELEASE >= 25).

escape(String) ->
    uri_string:quote(to_list(String)).

-else.

escape(String) ->
    http_uri:encode(to_list(String)).

-endif.

to_list(V) when is_atom(V) -> atom_to_list(V);
to_list(V) when is_binary(V) -> binary_to_list(V);
to_list(V) when is_list(V) -> V.
