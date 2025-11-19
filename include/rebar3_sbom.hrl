%--- Macros --------------------------------------------------------------------

-define(APP, "rebar3_sbom").
-define(DEFAULT_OUTPUT, "./bom.[xml|json]").
-define(DEFAULT_VERSION, 1).
-define(PROVIDER, sbom).
-define(DEPS, [lock]).
-define(SPEC_VERSION, <<"1.6">>).

%--- Types ---------------------------------------------------------------------

-type bom_ref() :: string().
-type spdx_licence_id() :: string().
-type properties() :: [{string(), string()}].

%--- Records -------------------------------------------------------------------

-record(address, {
    bom_ref :: bom_ref(),
    country :: string(),
    region :: string(),
    locality :: string(),
    post_office_box_number :: string(),
    postal_code :: string(),
    street_address :: string()
}).

-record(contact, {
    bom_ref :: bom_ref(),
    name :: string(),
    email :: string(),
    phone :: string()
 }).

% Alias Manufacturer object
-record(organization, {
    bom_ref :: bom_ref(),
    name :: string(),
    address :: #address{} | undefined,
    url :: string(),
    contact :: #contact{} | undefined
}).

% Alias Author
-record(individual, {
    bom_ref :: bom_ref(),
    name :: string(),
    email :: string(),
    phone :: string()
}).

-record(licensing, {
    alt_id :: string(),
    licensor :: #organization{} | #individual{},
    licensee :: #organization{} | #individual{},
    purchaser :: #organization{} | #individual{},
    purchase_order :: string(),
    licenses_types :: string(),
    last_renewal :: calendar:datetime(),
    expiration :: calendar:datetime()
}).

% Not adding Text or URL for now
-record(license, {
    bom_ref :: bom_ref(),
    id :: spdx_licence_id(),
    name :: string(),
    acknowledgement :: string(), % Either "declared" or "concluded",
    licensing :: #licensing{} | undefined,
    properties = [] :: properties()
}).

-record(component, {
    type = "application",
    bom_ref :: string(),
    authors = [] :: [#{name := string()}],
    name :: string(),
    version :: string(),
    description :: string(),
    hashes = [] :: [#{alg := string(), hash := string()}],
    licenses = [] :: [#{name := string()} | #{id := string()}],
    externalReferences = [] :: [#{type := string(), url := string()}],
    purl :: string()
}).

-record(metadata, {
    timestamp :: string(),
    component :: #component{},
    tools = [] :: [string()],
    properties = [] :: properties()
}).

-record(dependency, {
    ref :: string(),
    dependencies = [] :: [#dependency{}]
}).

-record(sbom, {
    format = "CycloneDX" :: string(),
    version = ?DEFAULT_VERSION :: integer(),
    serial :: string() | undefined,
    metadata :: #metadata{} | undefined,
    components :: [#component{}],
    dependencies = [] :: [#dependency{}]
}).
