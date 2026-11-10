"""ONVIF control: stream discovery, PTZ, IR-cut / day-night, relay (alarm) outputs.

IR is a camera hardware capability: software can only toggle the IR-cut filter. IrCutFilter
ON = day (filter blocks IR), OFF = night (IR passes, IR LEDs on), AUTO = camera photosensor.
"""
import threading
from urllib.parse import quote, urlsplit, urlunsplit

from fastapi import HTTPException

from . import models
from .security import dec

_cache: dict[int, object] = {}
_lock = threading.Lock()


def _connect(host, port, user, pw):
    try:
        from onvif import ONVIFCamera
        return ONVIFCamera(host, int(port), user, pw)
    except Exception as e:
        raise HTTPException(502, f"ONVIF connection failed: {e}")


def _cam(c: models.Camera):
    if not c.onvif_host:
        raise HTTPException(400, "Camera has no ONVIF host configured")
    with _lock:
        if c.id not in _cache:
            _cache[c.id] = _connect(c.onvif_host, c.onvif_port, c.onvif_user, dec(c.onvif_pass))
        return _cache[c.id]


def forget(cam_id: int):
    with _lock:
        _cache.pop(cam_id, None)


def _with_creds(uri: str, user: str, pw: str) -> str:
    p = urlsplit(uri)
    if not user or "@" in p.netloc:
        return uri
    return urlunsplit((p.scheme, f"{quote(user, safe='')}:{quote(pw, safe='')}@{p.netloc}",
                       p.path, p.query, p.fragment))


def probe(host: str, port: int, user: str, pw: str) -> list[dict]:
    cam = _connect(host, port, user, pw)
    try:
        media = cam.create_media_service()
        out = []
        for p in media.GetProfiles():
            uri = media.GetStreamUri({"StreamSetup": {"Stream": "RTP-Unicast", "Transport": {"Protocol": "RTSP"}},
                                      "ProfileToken": p.token}).Uri
            enc = getattr(p, "VideoEncoderConfiguration", None)
            res = getattr(enc, "Resolution", None) if enc else None
            out.append({"profile": p.Name, "token": p.token, "uri": _with_creds(uri, user, pw),
                        "width": getattr(res, "Width", None), "height": getattr(res, "Height", None),
                        "encoding": getattr(enc, "Encoding", None) if enc else None})
        out.sort(key=lambda x: -(x["width"] or 0))
        return out
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"ONVIF probe failed: {e}")


def _profile(cam):
    return cam.create_media_service().GetProfiles()[0]


def ptz(c: models.Camera, action: str, pan=0.0, tilt=0.0, zoom=0.0, preset: str = ""):
    cam = _cam(c)
    try:
        svc, prof = cam.create_ptz_service(), _profile(cam)
        if action == "stop":
            svc.Stop({"ProfileToken": prof.token, "PanTilt": True, "Zoom": True})
        elif action == "move":
            req = svc.create_type("ContinuousMove")
            req.ProfileToken = prof.token
            req.Velocity = {"PanTilt": {"x": pan, "y": tilt}, "Zoom": {"x": zoom}}
            svc.ContinuousMove(req)
        elif action == "goto_preset":
            svc.GotoPreset({"ProfileToken": prof.token, "PresetToken": preset})
        elif action == "presets":
            return [{"token": p.token, "name": p.Name} for p in svc.GetPresets({"ProfileToken": prof.token})]
    except Exception as e:
        forget(c.id)
        raise HTTPException(502, f"PTZ failed: {e}")


def set_ir(c: models.Camera, mode: str):
    """mode: day|night|auto"""
    cam = _cam(c)
    value = {"day": "ON", "night": "OFF", "auto": "AUTO"}[mode]
    try:
        img = cam.create_imaging_service()
        token = _profile(cam).VideoSourceConfiguration.SourceToken
        req = img.create_type("SetImagingSettings")
        req.VideoSourceToken = token
        req.ImagingSettings = {"IrCutFilter": value}
        req.ForcePersistence = True
        img.SetImagingSettings(req)
    except Exception as e:
        forget(c.id)
        raise HTTPException(502, f"IR switch failed (camera may lack IR-cut control): {e}")


def set_relay(c: models.Camera, active: bool):
    cam = _cam(c)
    try:
        token = c.relay_token
        if not token:
            relays = cam.devicemgmt.GetRelayOutputs()
            if not relays:
                raise HTTPException(400, "Camera exposes no relay outputs")
            token = relays[0].token
        cam.devicemgmt.SetRelayOutputState({"RelayOutputToken": token,
                                            "LogicalState": "active" if active else "inactive"})
    except HTTPException:
        raise
    except Exception as e:
        forget(c.id)
        raise HTTPException(502, f"Relay failed: {e}")
