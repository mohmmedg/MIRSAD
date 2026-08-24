from datetime import datetime
from pydantic import BaseModel, Field


class APIMethodObservation(BaseModel):
    method: str
    status_code: int | None = None
    allow_header: str | None = None
    content_type: str | None = None
    authenticated_status: int | None = None
    auth_status_delta: str | None = None
    skipped: bool = False
    note: str | None = None


class APIEndpoint(BaseModel):
    path: str
    url: str
    methods: list[str] = Field(default_factory=list)
    source: str = "discovery"
    security: list[str] = Field(default_factory=list)
    observations: list[APIMethodObservation] = Field(default_factory=list)


class OpenAPIParameter(BaseModel):
    name: str
    location: str
    required: bool = False
    schema_type: str | None = None
    format: str | None = None
    example_present: bool = False


class SchemaValidation(BaseModel):
    endpoint: str
    method: str
    direction: str
    status_code: int | None = None
    valid: bool | None = None
    errors: list[str] = Field(default_factory=list)


class OpenAPISummary(BaseModel):
    discovered: bool = False
    source_url: str | None = None
    version: str | None = None
    title: str | None = None
    server_urls: list[str] = Field(default_factory=list)
    endpoint_count: int = 0
    security_schemes: list[str] = Field(default_factory=list)
    global_security: bool = False
    parse_error: str | None = None
    parameters: list[OpenAPIParameter] = Field(default_factory=list)
    schema_validation: list[SchemaValidation] = Field(default_factory=list)


class GraphQLOperation(BaseModel):
    operation_type: str
    type_name: str
    fields: list[str] = Field(default_factory=list)


class GraphQLInfo(BaseModel):
    discovered: bool = False
    endpoint: str | None = None
    introspection_attempted: bool = False
    introspection_enabled: bool = False
    introspection_status: int | None = None
    query_type: str | None = None
    mutation_type: str | None = None
    subscription_type: str | None = None
    type_count: int = 0
    field_count: int = 0
    introspection_error: str | None = None
    operations: list[GraphQLOperation] = Field(default_factory=list)
    sensitive_field_hints: list[str] = Field(default_factory=list)


class APITemplateMatch(BaseModel):
    template_id: str
    title: str
    severity: str = "Info"
    endpoint: str
    evidence: str
    remediation: str


class JWTClaimsAnalysis(BaseModel):
    present: bool = False
    algorithm: str | None = None
    token_type: str | None = None
    issuer_present: bool = False
    audience_present: bool = False
    expiry_present: bool = False
    expiry_status: str | None = None
    not_before_present: bool = False
    sensitive_claims: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class APISecurityResult(BaseModel):
    scan_id: str
    module: str = "api_security"
    target: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    openapi: OpenAPISummary = Field(default_factory=OpenAPISummary)
    graphql: GraphQLInfo = Field(default_factory=GraphQLInfo)
    endpoints: list[APIEndpoint] = Field(default_factory=list)
    template_matches: list[APITemplateMatch] = Field(default_factory=list)
    auth_mode: str = "none"
    auth_present: bool = False
    auth_findings: list[str] = Field(default_factory=list)
    jwt_analysis: JWTClaimsAnalysis = Field(default_factory=JWTClaimsAnalysis)
    openapi_parameters: list[OpenAPIParameter] = Field(default_factory=list)
    schema_validations: list[SchemaValidation] = Field(default_factory=list)
    coverage: dict[str, object] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    error_message: str | None = None
