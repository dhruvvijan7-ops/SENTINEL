from sqlalchemy.orm import Session

from app.models.system_settings import SystemSettings


def get_system_settings(db: Session) -> SystemSettings:
    settings = db.get(SystemSettings, 1)
    if settings is None:
        settings = SystemSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings
