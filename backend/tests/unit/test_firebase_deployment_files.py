"""Static contracts for Firebase Hosting and Cloud Build manifests."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_firebase_rewrites_are_ordered_before_frontend_catch_all() -> None:
    config = json.loads((ROOT / "firebase.json").read_text(encoding="utf-8"))
    rewrites = config["hosting"]["rewrites"]

    assert [rule["source"] for rule in rewrites] == [
        "/readyz",
        "/healthz",
        "/api/**",
        "/ws/**",
        "/docs",
        "/openapi.json",
        "**",
    ]
    assert [rule["run"]["serviceId"] for rule in rewrites] == [
        "cynux-api",
        "cynux-api",
        "cynux-api",
        "cynux-api",
        "cynux-api",
        "cynux-api",
        "cynux-web",
    ]
    assert all(rule["run"]["region"] == "asia-south1" for rule in rewrites)
    assert all(rule["run"]["pinTag"] is True for rule in rewrites)


def test_firebase_alias_cannot_accidentally_target_an_existing_project() -> None:
    config = json.loads((ROOT / ".firebaserc").read_text(encoding="utf-8"))

    assert config == {"projects": {"production": "cynux-security-prod"}}


def test_cloud_build_produces_immutable_api_and_frontend_images() -> None:
    config = yaml.safe_load((ROOT / "cloudbuild.yaml").read_text(encoding="utf-8"))
    images = config["images"]

    assert images == [
        "asia-south1-docker.pkg.dev/$PROJECT_ID/cynux/api:${_IMAGE_TAG}",
        "asia-south1-docker.pkg.dev/$PROJECT_ID/cynux/frontend:${_IMAGE_TAG}",
    ]
    rendered = (ROOT / "cloudbuild.yaml").read_text(encoding="utf-8")
    assert "NEXT_PUBLIC_API_BASE_URL=" in rendered
    assert "NEXT_PUBLIC_WS_BASE_URL=" in rendered
    assert ".env" not in rendered


def test_container_context_excludes_secrets_and_frontend_defaults_to_cloud_run_port() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    dockerfile = (ROOT / "docker" / "frontend.Dockerfile").read_text(encoding="utf-8")

    assert "\n.env\n" in f"\n{dockerignore}"
    assert "*.env" in dockerignore
    assert "PORT=8080" in dockerfile
    assert "EXPOSE 8080" in dockerfile

