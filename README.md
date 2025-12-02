<!--
  SPDX-License-Identifier: BSD-3-Clause
  SPDX-FileCopyrightText: 2019 Bram Verburg
  SPDX-FileCopyrightText: 2024 Máté Lajkó
  SPDX-FileCopyrightText: 2025 Stritzinger GmbH
-->

rebar3_sbom
===========

Generates a Software Bill-of-Materials (SBoM) in CycloneDX format

Use
---

Add rebar3_sbom to your rebar config, either in a project or globally in
~/.config/rebar3/rebar.config:

    {plugins, [rebar3_sbom]}.

Then run the 'sbom' task on a project:

    $ rebar3 sbom
    ===> Verifying dependencies...
    ===> CycloneDX SBoM written to bom.xml

Configuration
-------------

You can configure additional SBoM metadata in your `rebar.config`:

    {rebar3_sbom, [
        {sbom_manufacturer, #{          % Optional, all fields inside are optional
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
        {sbom_licenses, ["Apache-2.0"]} % Optional
    ]}.

**Note:**
- `sbom_manufacturer` (optional) identifies who is **producing the SBoM document**
  (typically your organization or CI environment), not necessarily who developed
  the software. If omitted, the manufacturer field is not included in the SBoM.
- `sbom_licenses` (optional) specifies the licenses for the **SBoM document itself**
  (the metadata), not your project. If omitted, it defaults to the same licenses
  as your project (from the `.app.src` file).
- Your project's licenses are automatically read from the `.app.src` file and
  appear in `metadata.component.licenses`.


Command Line Options
--------------------

The following command line options are supported:

    -F, --format  the file format of the SBoM output, [xml|json], [default: xml]
    -o, --output  the full path to the SBoM output file [default: ./bom.[xml|json]]
    -f, --force   overwite existing files without prompting for confirmation
                  [default: false]
    -V, --strict_version modify the version number of the BoM only when the content changes
                  [default: true]
    -a  --author  the author of the SBoM

**Author Fallback:** If `--author` is not specified, the plugin will fall back
to the `GITHUB_ACTOR` environment variable. If that variable isn't set, it will
use the authors from the project's `.app.src` file.

By default only dependencies in the 'default' profile are included. To
generate an SBoM covering development environments specify the relevant
profiles using 'as':

    $ rebar3 as default,test,docs sbom -o dev_bom.xml

Hash Generation
---------------

For the main component (`metadata.component`), the plugin computes the SHA-256 hash of the release tarball (`<name>-<version>.tar.gz`) found in the release directory.

If the tarball does not exist (e.g., because `rebar3 tar` hasn't been run), no hash is included for the main component, and a warning is logged.

CPE Generation
--------------

The plugin automatically generates a CPE (Common Platform Enumeration) identifier for the main component (`metadata.component`) using the GitHub link from your project's `.app.src` file. If no GitHub link is present, the CPE field is omitted from the SBoM.

To ensure CPE generation, add a GitHub link to your `.app.src` file. For example:


    {application, my_app, [
        ...
        {links, [
            {"GitHub", "https://github.com/your-org/my_app"}
        ]}
    ]}.

External References
-------------------

The plugin supports external references for components, which are automatically extracted from the `links` field in your `.app.src` file or from Hex metadata for dependencies.

All standard CycloneDX external reference types are supported. Additionally, for convenience, the plugin supports common field names used by the Erlang/Elixir community, which are automatically mapped to their CycloneDX equivalents:

- `"GitHub"` → `"vcs"`
- `"Homepage"` → `"website"`
- `"Changelog"` → `"release-notes"`
- `"Issues"` → `"issue-tracker"`
- `"Documentation"` → `"documentation"`

**Note:** The plugin treats the names (i.e., `"Homepage"`, `"GitHub"`, etc.) in the `links` field as case-insensitive, so `"homepage"` and `"HOMEPAGE"` will also map to `"website"`, for example.

You can use either the standard CycloneDX type names or the community convention names in your `.app.src` file:

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
