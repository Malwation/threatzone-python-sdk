"""User and workspace type definitions."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class WorkspaceBasicInfo(BaseModel):
    """Basic workspace information from userInfo response."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    alias: str
    private: bool
    type: Literal["personal", "organization"]


class LimitsCount(BaseModel):
    """Current usage counts."""

    model_config = ConfigDict(populate_by_name=True)

    api_request_count: int = Field(alias="apiRequestCount")
    daily_submission_count: int = Field(alias="dailySubmissionCount")
    concurrent_submission_count: int = Field(alias="concurrentSubmissionCount")
    ai_report_count: int | None = Field(default=None, alias="aiReportCount")
    """AI report quota units used since 00:00 UTC. A report in progress counts as used."""
    ai_report_resets_at: datetime | None = Field(default=None, alias="aiReportResetsAt")
    """Time when the daily AI report quota resets (00:00 UTC)."""


class UserInfoDetails(BaseModel):
    """User details within UserInfo response."""

    model_config = ConfigDict(populate_by_name=True)

    email: str
    full_name: str = Field(alias="fullName")
    workspace: WorkspaceBasicInfo
    limits_count: LimitsCount = Field(alias="limitsCount")


class FileLimits(BaseModel):
    """File upload limits."""

    model_config = ConfigDict(populate_by_name=True)

    extensions: list[str]
    file_size: str = Field(alias="fileSize")


class SubmissionLimits(BaseModel):
    """Submission quota limits."""

    model_config = ConfigDict(populate_by_name=True)

    api_limit: int = Field(alias="apiLimit")
    daily_limit: int = Field(alias="dailyLimit")
    concurrent_limit: int = Field(alias="concurrentLimit")
    ai_report_limit: int | None = Field(default=None, alias="aiReportLimit")
    """Daily AI report limit. The value is 0 when the plan has no AI report."""


class PlanPermissions(BaseModel):
    """Plan permissions.

    A ``False`` value means that the matching routes return 403. A permission
    that the plan does not store is ``False``.
    """

    model_config = ConfigDict(populate_by_name=True)

    download_sample: bool | None = Field(default=None, alias="downloadSample")
    html_report: bool | None = Field(default=None, alias="htmlReport")
    stix_report: bool | None = Field(default=None, alias="stixReport")
    pdf_report: bool | None = Field(default=None, alias="pdfReport")
    download_report: bool | None = Field(default=None, alias="downloadReport")
    """Download report files, for example the network capture and the raw analysis data."""
    ai_report: bool | None = Field(default=None, alias="aiReport")
    """Read and queue AI analyst reports."""


class PlanInfo(BaseModel):
    """Workspace plan information."""

    model_config = ConfigDict(populate_by_name=True)

    plan_name: str = Field(alias="planName")
    start_time: str = Field(alias="startTime")
    end_time: str = Field(alias="endTime")
    subs_time: str = Field(alias="subsTime")
    file_limits: FileLimits = Field(alias="fileLimits")
    submission_limits: SubmissionLimits = Field(alias="submissionLimits")
    permissions: PlanPermissions | None = None


class ModuleInfo(BaseModel):
    """Module information."""

    model_config = ConfigDict(populate_by_name=True)

    module_id: str = Field(alias="moduleId")
    module_name: str = Field(alias="moduleName")
    start_time: str = Field(alias="startTime")
    end_time: str = Field(alias="endTime")


class UserInfo(BaseModel):
    """Current user information from /me endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    user_info: UserInfoDetails = Field(alias="userInfo")
    plan: PlanInfo
    modules: list[ModuleInfo]

    @property
    def workspace(self) -> WorkspaceBasicInfo:
        """Get workspace details (convenience accessor)."""
        return self.user_info.workspace

    @property
    def email(self) -> str:
        """Get user email."""
        return self.user_info.email

    @property
    def full_name(self) -> str:
        """Get user full name."""
        return self.user_info.full_name

    @property
    def workspace_name(self) -> str:
        """Get workspace name."""
        return self.user_info.workspace.name

    @property
    def workspace_alias(self) -> str:
        """Get workspace alias."""
        return self.user_info.workspace.alias

    @property
    def plan_permissions(self) -> PlanPermissions | None:
        """Get the plan permissions. ``None`` when the server does not send them."""
        return self.plan.permissions

    @property
    def ai_report_resets_at(self) -> datetime | None:
        """Get the time when the daily AI report quota resets."""
        return self.user_info.limits_count.ai_report_resets_at
