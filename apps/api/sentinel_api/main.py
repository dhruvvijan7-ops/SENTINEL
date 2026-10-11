from __future__ import annotations

import uvicorn

from sentinel_core.config import log_effective_config, load_settings

from .app import create_app


def main() -> None:
    settings = load_settings()
    app = create_app(settings)
    log_effective_config(settings)
    uvicorn.run(
        app,
        host=settings.server_host,
        port=settings.server_port,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
