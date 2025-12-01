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
  ];

  languages.erlang = {
    enable = true;
    # Switch back to normal packages when Erlang 28.2 is available there
    package = pkgs-unstable.beam28Packages.erlang;
  };
}
