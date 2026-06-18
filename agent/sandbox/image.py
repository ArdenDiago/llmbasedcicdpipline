"""Sandbox image management — ensure the runner image is available locally."""
from __future__ import annotations

import logging
from typing import Protocol

logger = logging.getLogger(__name__)

DEFAULT_IMAGE = "python:3.12-slim"


class _DockerClient(Protocol):
    images: "_Images"


class _Images(Protocol):
    def get(self, name: str): ...
    def pull(self, repository: str, tag: str | None = None): ...


def ensure_image(client: _DockerClient, image: str = DEFAULT_IMAGE):
    """Return the image if present locally, otherwise pull it.

    Raises docker.errors.ImageNotFound / APIError on unrecoverable failure.
    """
    try:
        img = client.images.get(image)
        logger.debug("image %s already present locally", image)
        return img
    except Exception as exc:
        logger.info("image %s missing locally (%s) — pulling", image, exc.__class__.__name__)

    if ":" in image:
        repo, tag = image.rsplit(":", 1)
    else:
        repo, tag = image, "latest"
    return client.images.pull(repo, tag=tag)
