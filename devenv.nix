# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation

{ pkgs, lib, config, inputs, ... }:
let
  # The Sphinx man builder fails to produce the "man" output.
  reuse = pkgs.reuse.overridePythonAttrs (old: {
    outputs = [ "out" ];
    dontUseSphinx = true;
  });
in
{
  packages = with pkgs; [
    git
    sbom-utility
    cyclonedx-cli
    reuse
  ];

  languages.erlang = {
    enable = true;
    package = pkgs.beam28Packages.erlang;
  };

  git-hooks.hooks = {
    erlfmt = {
      enable = true;
      name = "Erlfmt Check";
      entry = "rebar3 fmt --check";
      files = "\\.(erl|hrl|app.src|config)$";
      pass_filenames = false;
    };
    elvis = {
      enable = true;
      name = "Elvis Linter";
      entry = "rebar3 lint";
      files = "\\.(erl|hrl)$";
      pass_filenames = false;
    };
    reuse = {
      enable = true;
      package = reuse;
    };
  };
}
