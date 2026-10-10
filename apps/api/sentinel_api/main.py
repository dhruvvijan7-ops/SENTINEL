from __future__ import annotations

import uvicorn

from sentinel_core.config import load_settings

from .app import create_app


def main() -> None:
    settings = load_settings()
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.api_bind_host,
        port=settings.api_bind_port,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
