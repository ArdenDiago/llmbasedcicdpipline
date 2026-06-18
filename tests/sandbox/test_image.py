from __future__ import annotations

from unittest.mock import MagicMock

from agent.sandbox import image


def test_ensure_image_returns_local_when_present():
    client = MagicMock()
    client.images.get.return_value = MagicMock(id="local-id")

    result = image.ensure_image(client, "python:3.12-slim")

    assert result.id == "local-id"
    client.images.get.assert_called_once_with("python:3.12-slim")
    client.images.pull.assert_not_called()


def test_ensure_image_pulls_when_missing():
    client = MagicMock()
    client.images.get.side_effect = RuntimeError("not found")
    client.images.pull.return_value = MagicMock(id="pulled-id")

    result = image.ensure_image(client, "python:3.12-slim")

    assert result.id == "pulled-id"
    client.images.pull.assert_called_once_with("python", tag="3.12-slim")


def test_ensure_image_defaults_tag_to_latest():
    client = MagicMock()
    client.images.get.side_effect = RuntimeError("not found")
    client.images.pull.return_value = MagicMock(id="pulled")

    image.ensure_image(client, "myimage")

    client.images.pull.assert_called_once_with("myimage", tag="latest")
