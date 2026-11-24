import ipaddress

from django.conf import settings

USER_AGENT_MAX = 400


def _valid_ip(value):
    try:
        return ipaddress.ip_address((value or "").strip()).compressed
    except ValueError:
        return None


def get_client_ip(request):
    """
    Client IP, trusting X-Forwarded-For only for the configured number of proxies.
    With TRUSTED_PROXY_COUNT=0 the header is ignored entirely (anti-spoofing).
    """
    trusted = settings.TRUSTED_PROXY_COUNT
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if trusted > 0 and forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if len(parts) >= trusted:
            ip = _valid_ip(parts[-trusted])
            if ip:
                return ip
    return _valid_ip(request.META.get("REMOTE_ADDR"))


def get_user_agent(request):
    return (request.META.get("HTTP_USER_AGENT", "") or "")[:USER_AGENT_MAX]
