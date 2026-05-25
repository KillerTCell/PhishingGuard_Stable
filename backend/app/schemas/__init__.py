"""PhishGuard Pydantic v2 schema package.

Imports are grouped by router so IDE auto-import and ``from app.schemas import X``
both work without double-importing.  The ``common`` module (enums + pagination)
is imported first because all domain schemas depend on it.
"""
# Enums, pagination
from app.schemas.common import (
    AssistantRole,
    Classification,
    ConnectorStatus,
    DigestAction,
    EmailStatus,
    ErrorResponse,
    ExportDateRange,
    ExportFormat,
    ExportStatus,
    FeedbackLabel,
    FeedbackSource,
    FeedbackState,
    IngestionSource,
    InsightType,
    LabelFilter,
    Page,
    PaginatedResponse,
    RiskBand,
    Severity,
    SortDir,
    StatsPeriod,
    UserRole,
)

# Auth — Section 4.1
from app.schemas.auth import (
    AcceptInviteRequest,
    AcceptInviteResponse,
    ForgotPasswordRequest,
    InviteRequest,
    InviteResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
    ResetPasswordRequest,
)

# Emails — Section 4.2
from app.schemas.emails import (
    AttachmentMetadata,
    EmailDetail,
    EmailFeatureDetail,
    EmailListItem,
    EmailListResponse,
    EmailUploadResponse,
    LinkDetail,
)

# Analysis + Dashboard — Section 4.3
from app.schemas.analysis import (
    AnalysisStatusResponse,
    AnalysisStatsResponse,
    AssistantMessage,
    AssistantRequest,
    CurrentThreshold,
    DetectionDriverItem,
    InsightItem,
    PasteAnalysisRequest,
    PasteAnalysisResponse,
    RecentQuarantinedItem,
    SampleEmailResponse,
    SeverityDistribution,
)

# Quarantine — Section 4.4
from app.schemas.quarantine import (
    DigestPreviewResponse,
    QuarantineActionResponse,
    QuarantineListItem,
    QuarantineListResponse,
    SendDigestResponse,
)

# Forwarding Inbox — Section 4.6
from app.schemas.forwarding import (
    ForwardingConfigRequest,
    ForwardingConfigResponse,
    ForwardingEmailItem,
    ForwardingEmailListResponse,
    ForwardingStatusResponse,
    ForwardingTestResponse,
    SetupInstruction,
)

# Feedback + Digest action — Section 4.7
from app.schemas.feedback import (
    DigestActionParam,
    FeedbackRequest,
)

# Settings + Export — Section 4.8
from app.schemas.settings import (
    ExportCreateRequest,
    ExportCreateResponse,
    ExportJobStatusResponse,
    ExportScope,
    SettingsResponse,
    SettingsUpdateRequest,
)

# User Management — Section 4.9
from app.schemas.users import (
    RecentAuditAction,
    UserDetailResponse,
    UserListItem,
    UserStatsResponse,
    UserUpdateRequest,
)

# Notifications — Section 4.11
from app.schemas.notifications import NotificationsReadResponse

# Audit Log — Section 4.12
from app.schemas.audit import (
    AuditLogListItem,
    AuditLogListResponse,
)

# Health — Section 4.13
from app.schemas.health import HealthResponse

__all__ = [
    # common
    "AssistantRole",
    "Classification",
    "ConnectorStatus",
    "DigestAction",
    "EmailStatus",
    "ErrorResponse",
    "ExportDateRange",
    "ExportFormat",
    "ExportStatus",
    "FeedbackLabel",
    "FeedbackSource",
    "FeedbackState",
    "IngestionSource",
    "InsightType",
    "LabelFilter",
    "Page",
    "PaginatedResponse",
    "RiskBand",
    "Severity",
    "SortDir",
    "StatsPeriod",
    "UserRole",
    # auth
    "AcceptInviteRequest",
    "AcceptInviteResponse",
    "ForgotPasswordRequest",
    "InviteRequest",
    "InviteResponse",
    "LoginRequest",
    "LoginResponse",
    "MeResponse",
    "RefreshResponse",
    "RegisterRequest",
    "RegisterResponse",
    "ResetPasswordRequest",
    # emails
    "AttachmentMetadata",
    "EmailDetail",
    "EmailFeatureDetail",
    "EmailListItem",
    "EmailListResponse",
    "EmailUploadResponse",
    "LinkDetail",
    # analysis
    "AnalysisStatusResponse",
    "AnalysisStatsResponse",
    "AssistantMessage",
    "AssistantRequest",
    "CurrentThreshold",
    "DetectionDriverItem",
    "InsightItem",
    "PasteAnalysisRequest",
    "PasteAnalysisResponse",
    "RecentQuarantinedItem",
    "SampleEmailResponse",
    "SeverityDistribution",
    # quarantine
    "DigestPreviewResponse",
    "QuarantineActionResponse",
    "QuarantineListItem",
    "QuarantineListResponse",
    "SendDigestResponse",
    # forwarding
    "ForwardingConfigRequest",
    "ForwardingConfigResponse",
    "ForwardingEmailItem",
    "ForwardingEmailListResponse",
    "ForwardingStatusResponse",
    "ForwardingTestResponse",
    "SetupInstruction",
    # feedback
    "DigestActionParam",
    "FeedbackRequest",
    # settings
    "ExportCreateRequest",
    "ExportCreateResponse",
    "ExportJobStatusResponse",
    "ExportScope",
    "SettingsResponse",
    "SettingsUpdateRequest",
    # users
    "RecentAuditAction",
    "UserDetailResponse",
    "UserListItem",
    "UserStatsResponse",
    "UserUpdateRequest",
    # notifications
    "NotificationsReadResponse",
    # audit
    "AuditLogListItem",
    "AuditLogListResponse",
    # health
    "HealthResponse",
]
