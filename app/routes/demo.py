from fastapi import APIRouter
from fastapi.responses import RedirectResponse

from app.services.system_settings import get_admin_access_path

router = APIRouter(tags=["demo"])


@router.get("/")
def home():
    return RedirectResponse(url=f"/{get_admin_access_path()}/admin/login", status_code=302)


@router.get("/help")
def help_page():
    return RedirectResponse(
        url=f"/{get_admin_access_path()}/admin/login", status_code=302
    )
