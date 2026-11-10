from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration comes from VMS_* environment variables (see .env.example)."""

    model_config = SettingsConfigDict(env_prefix="VMS_")

    database_url: str = "sqlite:///./vms.db"
    secret_key: str                      # JWT signing key (>= 32 random bytes)
    fernet_key: str                      # encrypts camera credentials + TOTP secrets at rest
    internal_token: str                  # shared secret: api <-> mediamtx <-> worker
    mediamtx_api: str = "http://mediamtx:9997"

    cookie_secure: bool = True
    session_minutes: int = 30            # idle timeout (UI refreshes while active)
    session_max_hours: int = 12          # absolute timeout -> forces re-login with MFA
    stream_token_seconds: int = 600

    snapshot_dir: str = "/data/snapshots"
    event_retention_days: int = 30
    tz: str = "Asia/Kolkata"
    setup_code_file: str = ""            # first-run setup code (default: <data>/setup-code.txt, mode 0600)
    invite_hours: int = 72               # lifetime of invitation / password-reset links

    enrich_url: str = ""                 # cloud enrichment service (face / ANPR / re-ID)
    enrich_token: str = ""
    face_match_threshold: float = 0.45
    reid_match_threshold: float = 0.80

    twilio_sid: str = ""
    twilio_token: str = ""
    twilio_from: str = ""
    wa_token: str = ""
    wa_phone_id: str = ""
    wa_template: str = "security_alert"
    wa_lang: str = "en"
    wa_api_version: str = "v21.0"
    alarm_webhook_url: str = ""
    alarm_seconds: int = 30

    debug: bool = False

    # Privacy / campus attendance
    media_key: str = ""                  # base64, 32 bytes: AES-256-GCM key for blurred media + templates
    store_dir: str = "/data/store"
    face_det_model: str = "/models/face_detection_yunet_2023mar.onnx"
    face_rec_model: str = "/models/face_recognition_sface_2021dec.onnx"
    antispoof_dir: str = "/models/antispoof"   # MiniFASNetV2-SE FP32 + INT8 (suriAI/face-antispoof-onnx)
    attendance_match_threshold: float = 0.42
    attendance_match_margin: float = 0.06
    unblur_ttl_minutes: int = 15
    recording_retention_hours: int = 720
    ffmpeg: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True

    # Laptop / standalone mode (no Caddy): the API also serves the UI and proxies MediaMTX.
    web_dir: str = ""
    mtx_webrtc_url: str = "http://127.0.0.1:8889"
    mtx_hls_url: str = "http://127.0.0.1:8888"
    mtx_playback_url: str = "http://127.0.0.1:9996"
    demo_cameras: str = ""               # "Name|rtsp://...;Name2|rtsp://..." added once at startup


settings = Settings()
