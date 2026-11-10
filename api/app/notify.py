"""Outbound alerting: SMS (Twilio), WhatsApp (Meta Cloud API, approved template), alarm (ONVIF relay + webhook).

India: commercial SMS needs DLT registration (sender ID + template) with your operator;
swap the Twilio call for MSG91/Gupshup if your DLT entity is registered there.
WhatsApp business-initiated messages must use a pre-approved template.
"""
import logging
import threading

import httpx

from .config import settings

log = logging.getLogger("notify")


def _bg(fn, *a):
    threading.Thread(target=fn, args=a, daemon=True).start()


def send_sms(numbers: list[str], text: str):
    if not (settings.twilio_sid and settings.twilio_token and settings.twilio_from):
        log.info("SMS not configured; skipped %s", numbers)
        return
    url = f"https://api.twilio.com/2010-04-01/Accounts/{settings.twilio_sid}/Messages.json"
    for n in numbers:
        try:
            r = httpx.post(url, data={"To": n, "From": settings.twilio_from, "Body": text[:600]},
                           auth=(settings.twilio_sid, settings.twilio_token), timeout=10)
            r.raise_for_status()
        except Exception as e:
            log.warning("SMS to %s failed: %s", n, e)


def send_whatsapp(numbers: list[str], params: list[str]):
    if not (settings.wa_token and settings.wa_phone_id):
        log.info("WhatsApp not configured; skipped %s", numbers)
        return
    url = f"https://graph.facebook.com/{settings.wa_api_version}/{settings.wa_phone_id}/messages"
    for n in numbers:
        body = {"messaging_product": "whatsapp", "to": n.lstrip("+"), "type": "template",
                "template": {"name": settings.wa_template, "language": {"code": settings.wa_lang},
                             "components": [{"type": "body", "parameters":
                                             [{"type": "text", "text": p[:200]} for p in params]}]}}
        try:
            r = httpx.post(url, json=body, headers={"Authorization": f"Bearer {settings.wa_token}"}, timeout=10)
            r.raise_for_status()
        except Exception as e:
            log.warning("WhatsApp to %s failed: %s", n, e)


def fire_webhook(payload: dict):
    if not settings.alarm_webhook_url:
        return
    try:
        httpx.post(settings.alarm_webhook_url, json=payload, timeout=5)
    except Exception as e:
        log.warning("alarm webhook failed: %s", e)


def alarm(camera, payload: dict):
    """Activate the camera's relay output (siren/strobe), auto-release after alarm_seconds."""
    from . import onvif_ctl
    fire_webhook({**payload, "state": "on"})
    if camera.onvif_host:
        try:
            onvif_ctl.set_relay(camera, True)
            t = threading.Timer(settings.alarm_seconds, lambda: _release(camera, payload))
            t.daemon = True
            t.start()
        except Exception as e:
            log.warning("relay on cam%s failed: %s", camera.id, e)


def _release(camera, payload):
    from . import onvif_ctl
    try:
        onvif_ctl.set_relay(camera, False)
    except Exception as e:
        log.warning("relay off cam%s failed: %s", camera.id, e)
    fire_webhook({**payload, "state": "off"})


def dispatch(actions: dict, camera, text: str, wa_params: list[str], payload: dict):
    if actions.get("sms"):
        _bg(send_sms, actions["sms"], text)
    if actions.get("whatsapp"):
        _bg(send_whatsapp, actions["whatsapp"], wa_params)
    if actions.get("alarm"):
        _bg(alarm, camera, payload)
    elif actions.get("webhook"):
        _bg(fire_webhook, payload)


# ------------------------------------------------------------------ security alerts
def send_email(to: list[str], subject: str, body: str):
    if not (settings.smtp_host and settings.smtp_from and to):
        return
    import smtplib
    import ssl
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.smtp_from, ", ".join(to), subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
            if settings.smtp_starttls:
                s.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)
    except Exception as e:
        log.warning("security email failed: %s", e)


def security_alert(db, kind: str, actor: str, message: str, detail: dict | None = None, severity: str = "high"):
    """Persist + push to every admin/super admin console + SMS/WhatsApp/email to their contacts.
    Used for every export or unblur attempt (allowed or denied) and other privileged actions."""
    from sqlalchemy import select

    from . import models
    from .realtime import hub
    n = models.Notification(kind=kind, severity=severity, actor=actor, message=message[:500], detail=detail or {})
    db.add(n)
    db.commit()
    hub.publish({"type": "security", "notification": {"id": n.id, "ts": models.iso(n.ts), "kind": kind,
                                                      "severity": severity, "actor": actor, "message": n.message}},
                min_role="admin")
    admins = db.scalars(select(models.User).where(models.User.role.in_(["admin", "superadmin"]),
                                                  models.User.disabled.is_(False))).all()
    text = f"[Sentinel Attend security] {message}"
    phones = [u.phone for u in admins if u.phone]
    emails = [u.email for u in admins if u.email]
    if phones:
        _bg(send_sms, phones, text)
        _bg(send_whatsapp, phones, [kind.replace("_", " "), actor or "-", models.iso(n.ts) or "", message[:150]])
    if emails:
        _bg(send_email, emails, f"Security alert: {kind.replace('_', ' ')}", f"{message}\n\nActor: {actor}\nTime (UTC): {models.iso(n.ts)}\nDetail: {detail or {}}")
    return n
