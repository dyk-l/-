from datetime import datetime


def build_calendar_draft(title: str, start: str) -> dict[str, str]:
    parsed = datetime.fromisoformat(start)
    return {"title": title.strip(), "start": parsed.isoformat()}
