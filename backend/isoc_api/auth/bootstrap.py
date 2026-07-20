"""On first boot, create the admin user from env vars."""

from __future__ import annotations

from sqlalchemy import select

from ..db.enums import Role, UserStatus
from ..db.models import User
from ..db.session import AsyncSessionLocal
from ..logging_config import get_logger
from ..settings import settings
from .security import hash_password

logger = get_logger("isoc.auth.bootstrap")


async def ensure_bootstrap_admin() -> None:
    email = settings.isoc_bootstrap_admin_email.lower().strip()
    if not email:
        logger.info("bootstrap.admin.skipped", reason="no email configured")
        return

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(select(User).where(User.email == email))
        if existing:
            logger.info("bootstrap.admin.exists", email=email)
            return

        admin = User(
            email=email,
            password_hash=hash_password(settings.isoc_bootstrap_admin_password.get_secret_value()),
            role=Role.ADMIN,
            status=UserStatus.ACTIVE,
            full_name="EKSIR Admin",
        )
        session.add(admin)
        await session.commit()
        logger.warning(
            "bootstrap.admin.created",
            email=email,
            note="Change the password immediately via the UI.",
        )
