# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation

{ pkgs, lib, config, inputs, ... }:
let
  pkgs-unstable = import inputs.nixpkgs-unstable {
    system = pkgs.stdenv.system;
    config.allowUnfree = true;
  };
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
    # Switch back to normal packages when Erlang 28.2 is available there
    package = pkgs-unstable.beam28Packages.erlang;
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
  };
}
