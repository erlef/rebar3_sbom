<!--
  SPDX-License-Identifier: BSD-3-Clause
  SPDX-FileCopyrightText: 2019 Bram Verburg
  SPDX-FileCopyrightText: 2024 Stritzinger GmbH
-->

# Rebar3 SBoM

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![.github/workflows/branch_main.yml](https://github.com/erlef/rebar3_sbom/actions/workflows/branch_main.yml/badge.svg)](https://github.com/erlef/rebar3_sbom/actions/workflows/branch_main.yml)
[![REUSE status](https://api.reuse.software/badge/github.com/erlef/rebar3_sbom)](https://api.reuse.software/info/github.com/erlef/rebar3_sbom)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/erlef/rebar3_sbom/badge)](https://scorecard.dev/viewer/?uri=github.com/erlef/rebar3_sbom)
[![Coverage Status](https://coveralls.io/repos/github/erlef/rebar3_sbom/badge.svg?branch=main)](https://coveralls.io/github/erlef/rebar3_sbom?branch=main)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11547/badge)](https://www.bestpractices.dev/projects/11547)

Generates a Software Bill-of-Materials (SBoM) for [Rebar3](https://rebar3.org)
projects, that follows the [CycloneDX](https://cyclonedx.org) specification 
([1.6](https://spec.cyclonedx.org/1.6/)).

[CycloneDX](https://cyclonedx.org) is an open SBOM standard (maintained by the
[OWASP Foundation](https://owasp.org)) with broad support in security scanners,
dependency trackers, and compliance tools.

## What is a Software Bill of Materials (SBoM) and why use it?

In manufacturing, a Bill of Materials (BOM) is the list of raw materials, parts,
and sub-assemblies needed to build a product, so you know exactly what goes into
it, in what quantity, and from where. 

A **Software Bill of Materials (SBoM)** does the same for software: it **lists
the components of your application** (packages and libraries) along with their
`versions`, `source locations` (e.g. Hex, GitHub), `checksums` (cryptographic
hashes for integrity), and `licensing information`.

That visibility supports **supply chain tracking** (what is in the software and
where it came from), faster response to vulnerabilities by **matching components
against vulnerability databases to respond to CVEs**, and **licence and compliance
reporting** (e.g. audits and due diligence). That is why **many organisations
and regulations expect or require an SBoM for critical software** — e.g.
safety-critical sectors, government procurement, or customers requiring supply
chain transparency.

> #### Info {: .info}
>
> An SBoM is an inventory, not a certification. It does not claim that software is secure or compliant. It provides a factual inventory that other tools and processes use for security and compliance assessments.

## Installation

Add the plugin to your Rebar3 config, per project (recommended) or globally.

**1. Project (recommended)**. In the project's `rebar.config`:

```erlang
{plugins, [rebar3_sbom]}.
```

**2. Global**. In `~/.config/rebar3/rebar.config`:

```erlang
{plugins, [rebar3_sbom]}.
```

Now, when you run any rebar3 command (e.g. `rebar3 compile` or `rebar3 sbom`), the plugin will be fetched.

## Usage

From the project directory (where your `rebar.config` lives), run:

```bash
rebar3 sbom
```

Result:

```
===> Verifying dependencies...
===> CycloneDX SBoM written to bom.xml
```

By default the SBoM is written to `bom.xml` (or `bom.json` if you use `--format json`). 


See [Available options](#available-options) for all flags.

### Choosing which profiles to include

Only dependencies in the `default` profile are included by default. To generate an SBoM that also includes development dependencies (e.g. from the `test` or `docs` profiles), specify the profiles using `as`:

```bash
rebar3 as default,test,docs sbom -o dev_bom.xml
```

## Available options

The following command line options are supported:

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--format` | `-F` | The file format of the SBoM output: `xml` or `json` | `xml` |
| `--output` | `-o` | The full path to the SBoM output file | `./bom.xml` or `./bom.json` |
| `--force` | `-f` | Overwrite existing files without prompting for confirmation | `false` |
| `--strict_version` | `-V` | When true, the BOM version is incremented only if the set of components differs from the existing BOM file (if any). Changes to metadata, timestamp, or other fields do not trigger a version increment. | `true` |
| `--author` | `-a` | The author of the SBoM | `GITHUB_ACTOR` env var; if unset, `authors` from `.app.src` file|

To see all options and their descriptions, run: `rebar3 help sbom`.


## Configuration

Optional SBoM metadata, like `sbom_manufacturer` or `sbom_licenses`, is set in
`rebar.config` under the `rebar3_sbom` key. Both options are optional; omit them
if you don't need them.

Example:

```erlang
{rebar3_sbom, [
    {sbom_manufacturer, #{          % Optional; all fields inside are optional
        name => "Your Organization",
        url => ["https://example.com", "https://another-example.com"],
        address => #{
            country => "Country",
            region => "State",
            locality => "City",
            post_office_box_number => "1",
            postal_code => "12345",
            street_address => "Street Address"
        },
        contact => [
            #{name => "John Doe",
                email => "support@example.com",
                phone => "123456789"}
        ]
    }},
    {sbom_licenses, ["Apache-2.0"]}   % Optional; licenses for the SBoM document itself
]}.
```
- `sbom_manufacturer` — **Who is producing the SBoM** (e.g. your organisation or
  CI). If omitted, the `manufacturer` field is not included in the SBOM. All
  fields inside are optional.
- `sbom_licenses` — Licenses for the SBoM document itself (the metadata), not
  your project. If omitted, it defaults to your project's licenses from
  `.app.src`. In the generated SBoM, these appear under `metadata.licenses`.
  Your project's licenses are always read from `.app.src` and appear in
  `metadata.component.licenses`.

## Hash generation

For the main component (the root application described by the BOM, in CycloneDX `metadata.component`), the plugin computes the `SHA-256` hash of the release tarball (`<name>-<version>.tar.gz`). The tarball is looked for under `rel/<app_name>/` relative to the project base directory (e.g. after `rebar3 release` or `rebar3 tar`).

If the tarball does not exist, no hash is included for the main component, and a warning is logged.

## CPE Generation

The plugin automatically generates a CPE (Common Platform Enumeration) identifier for the main component (`metadata.component`) using the GitHub link from your project's `.app.src` file. Dependencies also get a CPE when the package has a GitHub link (e.g. from Hex metadata). If no GitHub link is present, the CPE field is omitted for that component.

To ensure CPE generation for the main component, add a GitHub link to your `.app.src` file. For example:

```erlang
{application, my_app, [
    ...
    {links, [{"GitHub", "https://github.com/your-org/my_app"}]}
]}.
```

## External References

The plugin supports external references for components, which are automatically extracted from the `links` field in your `.app.src` file or from Hex metadata for dependencies.

All standard CycloneDX external reference types are supported. Additionally, for convenience, the plugin supports common field names used by the Erlang/Elixir community, which are automatically mapped to their CycloneDX equivalents:

| Link name        | CycloneDX type     |
|------------------|--------------------|
| `"GitHub"`       | `"vcs"`            |
| `"Homepage"`     | `"website"`        |
| `"Changelog"`    | `"release-notes"`  |
| `"Issues"`       | `"issue-tracker"`  |
| `"Documentation"`| `"documentation"`   |

> #### Info {: .info}
>
> The plugin treats the names (i.e., `"Homepage"`, `"GitHub"`, etc.) in the `links` field as case-insensitive, so `"homepage"` and `"HOMEPAGE"` will also map to `"website"`, for example.

You can use either the standard CycloneDX type names or the community convention names in your `.app.src` file:

```erlang
{application, my_app, [
    ...
    {links, [
        {"GitHub", "https://github.com/example/my_app"},
        {"Homepage", "https://example.com"},
        {"Changelog", "https://github.com/example/my_app/releases"},
        {"Issues", "https://github.com/example/my_app/issues"},
        {"Documentation", "https://example.com/documentation"}
    ]}
]}.
```

## Merging and other ecosystems

This plugin only considers `Rebar3/Hex` and `Git` (GitHub, Bitbucket) dependencies. For a full deployment SBoM (e.g. including NPM or OS packages), generate multiple CycloneDX BOMs and merge them with a tool such as [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) using its merge command (e.g. `cyclonedx merge --input-files bom1.xml bom2.xml --output-file merged.xml`).

## Development

### Development environment

You can get Erlang, Rebar3, and the tools used by this project in either of these ways:

- **devenv**: From the repository root, run `devenv shell` to enter a shell 
  with Erlang, Rebar3, CycloneDX CLI, and other tools (see [devenv](https://devenv.sh)).
- **asdf**: With [asdf](https://asdf-vm.com/) installed, run `asdf install` in
  the repository root; versions are defined in [`.tool-versions`](https://github.com/erlef/rebar3_sbom/blob/main/.tool-versions).

Linting is configured in [`elvis.config`](elvis.config). Run `rebar3 lint` to
check code style before submitting.

### Contributing 

For guidelines on how to contribute (bug reports, feature proposals, pull
requests), see the [Contributing guide](https://github.com/erlef/rebar3_sbom/blob/main/.github/CONTRIBUTING.md).

### Generating documentation

With Erlang/OTP 27+ and Rebar3 available (e.g. `devenv shell` or `.tool-versions`):

```bash
rebar3 compile
rebar3 ex_doc
```

Open `doc/index.html` in a browser.

### Running tests

To run the full test suite locally, you need the CycloneDX CLI (`cyclonedx-cli`) available on your `PATH`, as it is used by `rebar3_sbom_validation_SUITE` to validate generated SBOMs.

For example, on macOS or Linux with Homebrew:

```bash
brew tap cyclonedx/cyclonedx
brew install cyclonedx/cyclonedx/cyclonedx-cli
```

More information about the tool: https://github.com/CycloneDX/cyclonedx-cli
