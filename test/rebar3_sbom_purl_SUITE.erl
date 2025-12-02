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
        local_purl_test
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
