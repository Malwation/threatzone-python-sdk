"""User and workspace type definitions."""

from __future__ import annotations

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


class PlanInfo(BaseModel):
    """Workspace plan information."""

    model_config = ConfigDict(populate_by_name=True)

    plan_name: str = Field(alias="planName")
    start_time: str = Field(alias="startTime")
    end_time: str = Field(alias="endTime")
    subs_time: str = Field(alias="subsTime")
    file_limits: FileLimits = Field(alias="fileLimits")
    submission_limits: SubmissionLimits = Field(alias="submissionLimits")


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
