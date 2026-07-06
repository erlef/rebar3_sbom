%% SPDX-License-Identifier: BSD-3-Clause
%% SPDX-FileCopyrightText: 2025 Stritzinger GmbH

-module(rebar3_sbom_purl_SUITE).

% CT Exports
-export([all/0]).

% Testcases
-export([hex_purl_test/1]).
-export([github_purl_test/1]).
-export([bitbucket_purl_test/1]).
-export([git_github_variants_test/1]).
-export([git_bitbucket_variants_test/1]).
-export([git_unsupported_host_test/1]).
-export([local_purl_test/1]).
-export([local_otp_app_purl_test/1]).
-export([otp_runtime_purl_test/1]).

% Includes
-include_lib("stdlib/include/assert.hrl").

%--- Common test functions -----------------------------------------------------

all() ->
    [
        hex_purl_test,
        github_purl_test,
        bitbucket_purl_test,
        git_github_variants_test,
        git_bitbucket_variants_test,
        git_unsupported_host_test,
        local_otp_app_purl_test,
        local_purl_test,
        otp_runtime_purl_test
    ].

%--- Test cases ----------------------------------------------------------------

hex_purl_test(_) ->
    Purl = rebar3_sbom_purl:hex("Rebar3_SBOM", "1.2.3"),
    ?assertEqual(<<"pkg:hex/rebar3_sbom@1.2.3">>, Purl).

github_purl_test(_) ->
    Purl = rebar3_sbom_purl:github("ExampleOrg/ExampleRepo", "1.0.0"),
    ?assertEqual(<<"pkg:github/exampleorg/examplerepo@1.0.0">>, Purl).

git_github_variants_test(_) ->
    Urls = [
        "git@github.com:ExampleOrg/ExampleRepo.git",
        "https://github.com/ExampleOrg/ExampleRepo.git",
        "git://github.com/ExampleOrg/ExampleRepo.git"
    ],
    lists:foreach(
        fun(Url) ->
            Purl = rebar3_sbom_purl:git("example_app", Url, "3.0.0"),
            ?assertEqual(<<"pkg:github/exampleorg/examplerepo@3.0.0">>, Purl)
        end,
        Urls
    ).

bitbucket_purl_test(_) ->
    Purl = rebar3_sbom_purl:bitbucket("ExampleOrg/ExampleRepo", "2.0.0"),
    ?assertEqual(<<"pkg:bitbucket/exampleorg/examplerepo@2.0.0">>, Purl).

git_bitbucket_variants_test(_) ->
    Urls = [
        "git@bitbucket.org:ExampleOrg/ExampleRepo.git",
        "https://bitbucket.org/ExampleOrg/ExampleRepo.git",
        "git://bitbucket.org/ExampleOrg/ExampleRepo.git"
    ],
    lists:foreach(
        fun(Url) ->
            Purl = rebar3_sbom_purl:git("example_app", Url, "4.0.0"),
            ?assertEqual(<<"pkg:bitbucket/exampleorg/examplerepo@4.0.0">>, Purl)
        end,
        Urls
    ).

git_unsupported_host_test(_) ->
    ?assertEqual(
        undefined,
        rebar3_sbom_purl:git(
            "example_app",
            "git@gitlab.com:ExampleOrg/ExampleRepo.git",
            "5.0.0"
        )
    ).

local_otp_app_purl_test(_) ->
    Purl = rebar3_sbom_purl:local_otp_app("Local-App", "0.9.0"),
    ?assertEqual(<<"pkg:otp/local-app@0.9.0">>, Purl).

local_purl_test(_) ->
    Purl = rebar3_sbom_purl:local("Local-App", "0.9.0"),
    ?assertEqual(<<"pkg:generic/local-app@0.9.0">>, Purl).

otp_runtime_purl_test(_) ->
    GH = <<"https://github.com/erlang/otp">>,
    Purl = rebar3_sbom_purl:otp_runtime(<<"erlang/otp">>, <<"28">>, GH),
    ?assertMatch(<<"pkg:otp/erlang%2Fotp@28?repository_url=", _/binary>>, Purl),
    %% Verify repository_url and vcs_url qualifiers are present
    PurlStr = binary_to_list(Purl),
    ?assertNotEqual(nomatch, string:find(PurlStr, "repository_url=")),
    ?assertNotEqual(nomatch, string:find(PurlStr, "vcs_url=")),
    ErtsPurl = rebar3_sbom_purl:otp_runtime(<<"erts">>, <<"15.2">>, GH),
    ?assertMatch(<<"pkg:otp/erts@15.2?repository_url=", _/binary>>, ErtsPurl),
    KernelPurl = rebar3_sbom_purl:otp_runtime(<<"kernel">>, <<"10.2">>, GH),
    ?assertMatch(<<"pkg:otp/kernel@10.2?repository_url=", _/binary>>, KernelPurl).
