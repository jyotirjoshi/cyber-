"""Bounded GitHub, GitLab and Bitbucket source snapshots for source-code scanners.

Only the explicitly approved canonical repository is fetched. A tenant token goes to its
provider API only, never to GitHub's short-lived redirect or a scanner container.
"""

from __future__ import annotations

import io
import re
import tarfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit

import httpx

from app.core.crypto import Secret
from app.core.errors import ScannerContainerError, UnsafeScannerInvocationError

_GITHUB_REPO = re.compile(
    r"\Ahttps://github\.com/(?P<owner>[A-Za-z0-9][A-Za-z0-9-]{0,38})/"
    r"(?P<repo>[A-Za-z0-9_.-]{1,100})\Z"
)
_GITLAB_REPO = re.compile(
    r"\Ahttps://gitlab\.com/(?P<owner>[A-Za-z0-9][A-Za-z0-9_.-]{0,100})/"
    r"(?P<repo>[A-Za-z0-9_.-]{1,100})\Z"
)
_BITBUCKET_REPO = re.compile(
    r"\Ahttps://bitbucket\.org/(?P<owner>[A-Za-z0-9][A-Za-z0-9_.-]{0,100})/"
    r"(?P<repo>[A-Za-z0-9_.-]{1,100})\Z"
)
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES = 10_000
MAX_MEMBERS = 20_000


def github_coordinates(target: str) -> tuple[str, str]:
    match = _GITHUB_REPO.fullmatch(target)
    if not match or match.group("repo") in {".", ".."}:
        raise UnsafeScannerInvocationError(
            "Source scanning requires one canonical GitHub repository URL."
        )
    return match.group("owner"), match.group("repo")


def repository_coordinates(target: str) -> tuple[str, str, str]:
    for provider, pattern in (
        ("github", _GITHUB_REPO),
        ("gitlab", _GITLAB_REPO),
        ("bitbucket", _BITBUCKET_REPO),
    ):
        match = pattern.fullmatch(target)
        if match and match.group("repo") not in {".", ".."}:
            return provider, match.group("owner"), match.group("repo")
    raise UnsafeScannerInvocationError("Source scanning requires a supported canonical repository URL.")


def _download_archive(owner: str, repo: str, token: Secret | None = None) -> bytes:
    # GitHub's documented tarball API resolves the current default branch. Follow
    # exactly one redirect, only to the matching repository on codeload.github.com.
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball"
    data = bytearray()
    deadline = time.monotonic() + 120
    try:
        with httpx.Client(follow_redirects=False, trust_env=False, timeout=30.0) as client:
            headers = {"Accept": "application/vnd.github+json"}
            if token is not None:
                headers["Authorization"] = f"Bearer {token.reveal()}"
            redirect = client.get(url, headers=headers)
            if redirect.status_code != 302:
                raise ScannerContainerError("GitHub did not resolve the public repository archive.")
            location = redirect.headers.get("location", "")
            parsed = urlsplit(location)
            if (
                len(location) > 2048
                or parsed.scheme != "https"
                or parsed.hostname != "codeload.github.com"
                or parsed.port is not None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
                or not parsed.path.lower().startswith(f"/{owner}/{repo}/".lower())
                or "%" in parsed.path
            ):
                raise UnsafeScannerInvocationError("GitHub returned an unsafe archive redirect.")
            with client.stream(
                "GET", location, headers={"Accept": "application/octet-stream"}
            ) as response:
                response.raise_for_status()
                if response.status_code != 200:
                    raise ScannerContainerError("GitHub did not return a source archive.")
                for chunk in response.iter_bytes():
                    if time.monotonic() > deadline:
                        raise ScannerContainerError("Repository snapshot download timed out.")
                    data.extend(chunk)
                    if len(data) > MAX_ARCHIVE_BYTES:
                        raise UnsafeScannerInvocationError(
                            "Repository archive exceeds the size limit."
                        )
    except httpx.HTTPError as exc:
        raise ScannerContainerError(
            "Could not fetch the approved public GitHub repository snapshot.",
            cause=exc,
        ) from exc
    return bytes(data)


def _download_gitlab_archive(owner: str, repo: str, token: Secret | None = None) -> bytes:
    project = quote(f"{owner}/{repo}", safe="")
    url = f"https://gitlab.com/api/v4/projects/{project}/repository/archive.tar.gz"
    headers = {"Accept": "application/octet-stream"}
    if token is not None:
        headers["PRIVATE-TOKEN"] = token.reveal()
    data = bytearray()
    deadline = time.monotonic() + 120
    try:
        with (
            httpx.Client(follow_redirects=False, trust_env=False, timeout=30.0) as client,
            client.stream("GET", url, headers=headers) as response,
        ):
            response.raise_for_status()
            if response.status_code != 200:
                raise ScannerContainerError("GitLab did not return a source archive.")
            for chunk in response.iter_bytes():
                if time.monotonic() > deadline:
                    raise ScannerContainerError("Repository snapshot download timed out.")
                data.extend(chunk)
                if len(data) > MAX_ARCHIVE_BYTES:
                    raise UnsafeScannerInvocationError("Repository archive exceeds the size limit.")
    except httpx.HTTPError as exc:
        raise ScannerContainerError("Could not fetch the approved GitLab repository snapshot.", cause=exc) from exc
    return bytes(data)


def _download_bitbucket_archive(owner: str, repo: str, token: Secret, account_email: str) -> bytes:
    if not re.fullmatch(r"[^\s:@]+@[^\s:@]+", account_email):
        raise UnsafeScannerInvocationError("Bitbucket account email is invalid.")
    auth = httpx.BasicAuth(account_email, token.reveal())
    metadata_url = f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo}"
    data = bytearray()
    deadline = time.monotonic() + 120
    try:
        with httpx.Client(follow_redirects=False, trust_env=False, timeout=30.0) as client:
            metadata_response = client.get(
                metadata_url, headers={"Accept": "application/json"}, auth=auth
            )
            metadata_response.raise_for_status()
            if metadata_response.status_code != 200:
                raise ScannerContainerError("Bitbucket did not return repository metadata.")
            metadata = metadata_response.json()
            if not isinstance(metadata, dict):
                raise UnsafeScannerInvocationError("Bitbucket repository metadata is invalid.")
            branch_info = metadata.get("mainbranch")
            branch = branch_info.get("name") if isinstance(branch_info, dict) else None
            if (
                str(metadata.get("full_name", "")).casefold() != f"{owner}/{repo}".casefold()
                or metadata.get("scm") != "git"
                or not isinstance(branch, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,200}", branch)
                or any(part in {".", ".."} for part in branch.split("/"))
            ):
                raise UnsafeScannerInvocationError("Bitbucket returned an invalid repository or branch.")
            archive_url = f"https://bitbucket.org/{owner}/{repo}/get/{quote(branch, safe='')}.gz"
            with client.stream("GET", archive_url, auth=auth) as response:
                response.raise_for_status()
                if response.status_code != 200:
                    raise ScannerContainerError("Bitbucket did not return a source archive.")
                for chunk in response.iter_bytes():
                    if time.monotonic() > deadline:
                        raise ScannerContainerError("Repository snapshot download timed out.")
                    data.extend(chunk)
                    if len(data) > MAX_ARCHIVE_BYTES:
                        raise UnsafeScannerInvocationError("Repository archive exceeds the size limit.")
    except (httpx.HTTPError, ValueError) as exc:
        raise ScannerContainerError("Could not fetch the approved Bitbucket repository snapshot.", cause=exc) from exc
    return bytes(data)


def stage_public_github_repo(
    target: str, workdir: Path, token: Secret | None = None
) -> Path:
    owner, repo = github_coordinates(target)
    archive_bytes = (
        _download_archive(owner, repo, token) if token is not None else _download_archive(owner, repo)
    )
    return _stage_archive_bytes(archive_bytes, workdir)


def stage_repository_snapshot(
    target: str,
    workdir: Path,
    token: Secret | None = None,
    *,
    account_email: str | None = None,
) -> Path:
    provider, owner, repo = repository_coordinates(target)
    if provider == "bitbucket":
        if token is None or account_email is None:
            raise UnsafeScannerInvocationError("Bitbucket requires a tenant repository credential.")
        return _stage_archive_bytes(
            _download_bitbucket_archive(owner, repo, token, account_email), workdir
        )
    if provider == "github":
        return stage_public_github_repo(target, workdir, token)
    return _stage_archive_bytes(_download_gitlab_archive(owner, repo, token), workdir)


def _stage_archive_bytes(archive_bytes: bytes, workdir: Path) -> Path:
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise UnsafeScannerInvocationError("Repository archive exceeds the size limit.")
    destination = workdir / "src"
    destination.mkdir(parents=True, exist_ok=True)
    root: str | None = None
    total = 0
    count = 0
    members = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for member in archive:
                members += 1
                if members > MAX_MEMBERS or len(member.name) > 1024:
                    raise UnsafeScannerInvocationError("Repository archive exceeds entry limits.")
                path = PurePosixPath(member.name)
                parts = path.parts
                if (
                    not parts
                    or path.is_absolute()
                    or any(part in {".", ".."} for part in parts)
                    or "\\" in member.name
                    or ":" in member.name
                ):
                    raise UnsafeScannerInvocationError("Repository archive has an unsafe path.")
                if root is None:
                    root = parts[0]
                if parts[0] != root:
                    raise UnsafeScannerInvocationError("Repository archive has multiple roots.")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise UnsafeScannerInvocationError(
                        "Repository archive contains a special file."
                    )
                if len(parts) < 2 or member.size > MAX_FILE_BYTES:
                    raise UnsafeScannerInvocationError(
                        "Repository archive contains an oversized file."
                    )
                count += 1
                total += member.size
                if count > MAX_FILES or total > MAX_EXPANDED_BYTES:
                    raise UnsafeScannerInvocationError(
                        "Repository snapshot exceeds extraction limits."
                    )
                output = destination.joinpath(*parts[1:])
                output.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise UnsafeScannerInvocationError(
                        "Repository archive contains an unreadable file."
                    )
                with source, output.open("xb") as sink:
                    remaining = member.size
                    while remaining:
                        chunk = source.read(min(65536, remaining))
                        if not chunk:
                            raise UnsafeScannerInvocationError("Repository archive is truncated.")
                        sink.write(chunk)
                        remaining -= len(chunk)
        if count == 0:
            raise UnsafeScannerInvocationError("Repository snapshot contains no files.")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UnsafeScannerInvocationError(
            "Repository archive could not be safely extracted."
        ) from exc
    return destination


__all__ = [
    "github_coordinates",
    "repository_coordinates",
    "stage_public_github_repo",
    "stage_repository_snapshot",
]
