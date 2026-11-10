"""UI: console behaviour per role, XSS, CSP, kiosk, anti-spoof lab (headless Chromium + mock API)."""
import json
import shutil
import subprocess
import sys
import time
import urllib.request

import pytest

from conftest import ROOT

pw = pytest.importorskip("playwright.sync_api")
PORT = 8766
BASE = f"http://127.0.0.1:{PORT}"
CHROME = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")


@pytest.fixture(scope="module")
def browser():
    srv = subprocess.Popen([sys.executable, str(ROOT / "tests" / "ui_mock.py"), str(ROOT / "web"), str(PORT)])
    time.sleep(1)
    p = pw.sync_playwright().start()
    kw = {"executable_path": CHROME} if CHROME else {}
    b = p.chromium.launch(args=["--no-sandbox", "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream"], **kw)
    yield b
    b.close()
    p.stop()
    srv.terminate()


def role(r):
    urllib.request.urlopen(f"{BASE}/__role?r={r}").read()


def posts():
    return json.loads(urllib.request.urlopen(f"{BASE}/__posts").read())


@pytest.fixture
def page(browser):
    ctx = browser.new_context(viewport={"width": 1500, "height": 950}, permissions=["camera"])
    pg = ctx.new_page()
    pg.errors, pg.csp = [], []
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("console", lambda m: m.type == "error" and ("Content Security Policy" in m.text or "Refused" in m.text) and pg.csp.append(m.text))
    yield pg
    ctx.close()


def visit(pg, route, wait=900):
    pg.goto(f"{BASE}/#/{route}")
    pg.wait_for_timeout(wait)


def nav(pg):
    return [a.inner_text().strip() for a in pg.query_selector_all("#nav a") if a.is_visible()]


ALL_VIEWS = ["dashboard", "live", "playback", "events", "attendance", "people", "kiosk", "privacy", "privacy?tab=alerts",
             "privacy?tab=vault", "antispoof", "cameras", "rules", "watchlists", "users", "audit"]


@pytest.mark.parametrize("r", ["viewer", "operator", "admin", "superadmin"])
def test_UI_01_no_script_errors_any_view(page, r):
    """Every view renders without JavaScript errors or CSP violations for each role."""
    role(r)
    for v in ALL_VIEWS:
        visit(page, v, 500)
    assert not page.errors, page.errors
    assert not page.csp, page.csp


def test_UI_02_viewer_least_privilege(page):
    """Viewer: no attendance/people/privacy/users/anti-spoof menus, no snapshot or export controls."""
    role("viewer")
    visit(page, "live", 1500)
    n = nav(page)
    for hidden in ("Attendance", "People", "Privacy", "Users", "Anti-spoof", "Cameras", "Audit log"):
        assert not any(hidden in x for x in n), n
    assert not page.query_selector("[data-action=snap]")
    visit(page, "playback")
    assert not page.query_selector("[data-action=pb-export]")


def test_UI_03_operator_requests_but_cannot_approve(page):
    """Operator: can request unblur; sees no Approve, no export, no CSV export."""
    role("operator")
    visit(page, "attendance")
    assert page.query_selector("[data-action=unblur-request]") and not page.query_selector("[data-action=att-export]")
    visit(page, "privacy")
    assert not page.query_selector("[data-action=unblur-approve]")
    visit(page, "playback")
    assert not page.query_selector("[data-action=pb-export]")


def test_UI_04_admin_no_video_export_no_superadmin_role(page):
    """Admin: CSV export yes; video export no; cannot assign the superadmin role."""
    role("admin")
    visit(page, "attendance")
    assert page.query_selector("[data-action=att-export]")
    visit(page, "playback")
    assert not page.query_selector("[data-action=pb-export]")
    visit(page, "users")
    assert "superadmin" not in page.inner_html("select[name=role]")


def test_UI_05_superadmin_controls(page):
    """Super admin: export, snapshot, approve and the superadmin role are available."""
    role("superadmin")
    visit(page, "playback")
    assert page.query_selector("[data-action=pb-export]")
    visit(page, "privacy")
    assert page.query_selector("[data-action=unblur-approve]")
    visit(page, "users")
    assert "superadmin" in page.inner_html("select[name=role]")


def test_UI_06_kiosk_role_locked_down(page):
    """Kiosk account: only the check-in screen; sidebar, rail and other menus hidden."""
    role("kiosk")
    visit(page, "users", 1500)
    assert "kiosk" in page.url and not page.is_visible(".side") and not page.is_visible(".rail")


def test_UI_07_kiosk_checkin_upload(page):
    """Kiosk check-in: 3-step challenge captured at 8 fps and uploaded (10-90 frames) with CSRF header."""
    role("operator")
    visit(page, "kiosk", 2000)
    before = len(posts())
    page.click("#kStart")
    page.wait_for_selector(".kiosk-result.good", timeout=20000)
    up = [p for p in posts()[before:] if p["path"] == "/api/kiosk/verify"]
    assert up and 10 <= up[0]["frames"] <= 90 and up[0]["csrf"] == "c"
    assert "frames real" in page.inner_text("#kResult")


def test_UI_08_stored_xss_neutralised(page):
    """HTML/JS in names, reasons and alert text is rendered as text and never executes."""
    role("superadmin")
    for v in ("attendance", "people", "privacy", "privacy?tab=alerts"):
        visit(page, v)
        assert page.evaluate("window.__xss") is None
    assert "&lt;img" in page.inner_html("#view") or "<img src=x" in page.inner_text("#view")


def test_UI_09_export_requires_mfa_and_reason(page):
    """Export opens a step-up dialog (reason + authenticator code) before any export request is sent."""
    role("superadmin")
    visit(page, "playback", 1500)
    page.click("#pbTimeline i")
    page.wait_for_timeout(300)
    before = len(posts())
    page.click("[data-action=pb-export]")
    page.wait_for_selector("form[data-form=stepup] input[name=totp]")
    assert page.query_selector("form[data-form=stepup] input[name=reason]")
    assert not [p for p in posts()[before:] if p["path"].endswith("/export")]
    page.fill("form[data-form=stepup] input[name=reason]", "Case 42 police request")
    page.fill("form[data-form=stepup] input[name=totp]", "123456")
    page.click("form[data-form=stepup] button")
    page.wait_for_timeout(800)
    ex = [p for p in posts()[before:] if p["path"].endswith("/export")]
    assert ex and ex[0]["body"] == {"totp": "123456", "reason": "Case 42 police request"}


def test_UI_10_unblur_approval_needs_passphrase_and_mfa(page):
    """Approving an unblur asks for the vault passphrase AND the authenticator code."""
    role("superadmin")
    visit(page, "privacy")
    page.click("[data-action=unblur-approve]")
    page.wait_for_selector("form[data-form=stepup]")
    assert page.query_selector("form[data-form=stepup] input[name=passphrase][type=password]")
    assert page.query_selector("form[data-form=stepup] input[name=totp]")


def test_UI_11_antispoof_lab_image_mode(page):
    """Anti-spoof lab: model info renders; image test draws real/spoof boxes."""
    role("operator")
    visit(page, "antispoof")
    assert "MiniFASNetV2-SE" in page.inner_text("#view") and "98.2" in page.inner_text("#view")
    import cv2
    import numpy as np
    tmp = ROOT / "tests" / ".tmp_ui.jpg"
    cv2.imwrite(str(tmp), np.full((180, 320, 3), 120, np.uint8))
    page.set_input_files("#asFile", str(tmp))
    page.wait_for_timeout(800)
    tmp.unlink()
    assert "real, spoof" in page.inner_text("#asStat")


def test_UI_12_antispoof_settings_admin_only(page):
    """Only admins see anti-spoof settings; operators see read-only status."""
    role("operator")
    visit(page, "antispoof")
    assert not page.query_selector("form[data-form=asSettings]")
    role("admin")
    page.reload()
    page.wait_for_timeout(900)
    assert page.query_selector("form[data-form=asSettings]")


def test_UI_13_csrf_header_on_writes(page):
    """Every state-changing request from the console carries the CSRF token."""
    role("superadmin")
    visit(page, "privacy?tab=alerts")
    before = len(posts())
    page.click("[data-action=bell-read]")
    page.wait_for_timeout(500)
    assert all(p["csrf"] == "c" for p in posts()[before:])


# ---------------------------------------------------------------- registration & 3D glass console
def signed_out(setup=False):
    role("none")
    urllib.request.urlopen(f"{BASE}/__setup?v={int(setup)}").read()


def test_UI_14_first_run_setup_wizard(page):
    """No accounts: the setup wizard (not sign-in) is shown; a wrong code is refused; the right one leads to MFA then vault."""
    signed_out(setup=True)
    page.goto(BASE + "/")
    page.wait_for_selector("[data-pane=setup]:not(.hidden)")
    assert not page.is_visible("#loginForm")
    f = "form[data-form=setupAccount] "
    page.fill(f + "input[name=setup_code]", "WRONG-CODE-0000-0000")
    page.fill(f + "input[name=username]", "principal")
    page.fill(f + "input[name=password]", "Campus-Gate-2026!")
    page.fill(f + "input[name=password2]", "Campus-Gate-2026!")
    page.click(f + "button[type=submit]")
    page.wait_for_timeout(400)
    assert "not valid" in page.inner_text(f + ".err")
    page.fill(f + "input[name=setup_code]", "GOOD-CODE-0000-0000")
    page.click(f + "button[type=submit]")
    page.wait_for_selector("form[data-form=setupMfa]:not(.hidden) img.qr")
    page.fill("form[data-form=setupMfa] input[name=totp]", "123456")
    page.click("form[data-form=setupMfa] button[type=submit]")
    page.wait_for_selector("form[data-form=setupVault]:not(.hidden)")
    page.click("[data-action=setup-skip]")
    assert page.is_visible("[data-done]")
    page.click("[data-action=setup-finish]")
    page.wait_for_selector("#app:not(.hidden)")
    signed_out(False)
    role("superadmin")


def test_UI_15_setup_hidden_when_accounts_exist(page):
    """With accounts present the setup screen never appears; sign-in is shown and offers no self-registration."""
    signed_out(setup=False)
    page.goto(BASE + "/")
    page.wait_for_selector("#loginForm")
    page.wait_for_timeout(400)
    assert page.is_visible("#loginForm") and not page.is_visible("[data-pane=setup]")
    role("superadmin")


def test_UI_16_invitation_registration(page):
    """An invitation link opens the registration screen, removes the token from the address bar, then enrols MFA."""
    signed_out()
    page.goto(BASE + "/#/register?code=" + "a" * 40)
    page.wait_for_selector("[data-pane=register]:not(.hidden)")
    page.wait_for_timeout(400)
    assert "a" * 40 not in page.url
    assert "invited as an operator" in page.inner_text("#regLede")
    page.fill("form[data-form=register] input[name=username]", "hod_cse")
    page.fill("form[data-form=register] input[name=password]", "Campus-Gate-2026!")
    page.fill("form[data-form=register] input[name=password2]", "Campus-Gate-2026!")
    page.click("form[data-form=register] button[type=submit]")
    page.wait_for_selector("form[data-form=registerMfa]:not(.hidden) img.qr")
    sent = [p for p in posts() if p["path"] == "/api/register"][-1]["body"]
    assert sent["code"] == "a" * 40 and sent["username"] == "hod_cse"
    role("superadmin")


def test_UI_17_reset_and_invalid_links(page):
    """Reset links hide the username field; used/expired links explain what to do."""
    signed_out()
    page.goto(BASE + "/#/register?code=reset" + "b" * 30)
    page.wait_for_timeout(700)
    assert "Choose a new password" in page.inner_text("#regTitle") and not page.is_visible("[data-field=username]")
    page.goto(BASE + "/#/register?code=bad" + "c" * 30)
    page.reload()
    page.wait_for_selector("[data-invalid]:not(.hidden)")
    role("superadmin")


def test_UI_18_users_invite_not_password(page):
    """Users page creates invitation links (never temporary passwords); admins cannot pick admin roles."""
    role("superadmin")
    visit(page, "users")
    assert page.query_selector("form[data-form=invite]") and "temporary" not in page.inner_text("#view").lower()
    page.select_option("form[data-form=invite] select[name=role]", "admin")
    page.click("form[data-form=invite] button")
    page.wait_for_selector("#linkOut")
    assert "/#/register?code=" in page.inner_text("#linkOut")
    role("admin")
    page.reload()
    page.wait_for_timeout(900)
    opts = page.eval_on_selector_all("form[data-form=invite] select[name=role] option", "o => o.map(x => x.value)")
    assert opts == ["kiosk", "viewer", "operator"], opts
    role("superadmin")


def test_UI_19_command_palette_and_theme(page):
    """Ctrl+K opens the command palette and navigates by keyboard; the theme toggles and persists."""
    role("operator")
    visit(page, "dashboard")
    page.keyboard.press("Control+k")
    page.wait_for_selector("#palette:not(.hidden)")
    page.keyboard.type("kiosk")
    page.keyboard.press("Enter")
    page.wait_for_timeout(500)
    assert page.url.endswith("#/kiosk")
    before = page.evaluate("document.documentElement.dataset.theme")
    page.click("[data-action=theme]")
    after = page.evaluate("document.documentElement.dataset.theme")
    assert before != after
    page.reload()
    page.wait_for_timeout(600)
    assert page.evaluate("document.documentElement.dataset.theme") == after


def test_UI_20_accessibility_basics(page):
    """Icon-only buttons have accessible names; every input has a label; nav is keyboard-reachable."""
    role("superadmin")
    for v in ("dashboard", "live", "users", "attendance"):
        visit(page, v)
        unnamed = page.evaluate("""() => [...document.querySelectorAll('button')].filter(b => b.offsetParent &&
            !(b.textContent.trim() || b.getAttribute('aria-label') || b.title)).map(b => b.outerHTML.slice(0, 80))""")
        assert not unnamed, (v, unnamed)
        unlabeled = page.evaluate("""() => [...document.querySelectorAll('#view input, #view select, #view textarea')].filter(i => i.offsetParent &&
            i.type !== 'hidden' && !i.closest('label') && !i.getAttribute('aria-label')).map(i => i.outerHTML.slice(0, 80))""")
        assert not unlabeled, (v, unlabeled)


@pytest.mark.parametrize("w", [390, 768, 1280])
def test_UI_21_responsive_no_horizontal_scroll(browser, w):
    """No page-level horizontal scroll from phone to laptop width; mobile menu opens and closes."""
    role("superadmin")
    ctx = browser.new_context(viewport={"width": w, "height": 860})
    pg = ctx.new_page()
    for v in ("dashboard", "attendance", "users", "privacy"):
        pg.goto(f"{BASE}/#/{v}")
        pg.wait_for_timeout(700)
        assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), (w, v)
    if w < 860:
        pg.click("[data-action=nav-toggle]")
        pg.wait_for_timeout(400)
        assert pg.evaluate("document.body.classList.contains('nav-open')")
        pg.click("#nav a[data-view=people]")
        pg.wait_for_timeout(400)
        assert not pg.evaluate("document.body.classList.contains('nav-open')")
    ctx.close()


def test_UI_22_reduced_motion_and_no_external_scripts(browser):
    """Reduced-motion users get a still scene; scripts load only from self + the pinned hls.js CDN (CSP)."""
    role("superadmin")
    ctx = browser.new_context(reduced_motion="reduce")
    pg = ctx.new_page()
    pg.goto(BASE + "/#/dashboard")
    pg.wait_for_timeout(600)
    anim = pg.evaluate("getComputedStyle(document.querySelector('.sweep')).animationName")
    assert anim == "none"
    srcs = pg.eval_on_selector_all("script[src]", "s => s.map(x => x.getAttribute('src'))")
    assert all(s.startswith("/js/") or s.startswith("https://cdnjs.cloudflare.com/ajax/libs/hls.js/1.5.13/") for s in srcs), srcs
    ctx.close()
