# Sentinel Attend test suite

Run everything (inside the app's own environment) and get an HTML report:

```
python run.py --selftest --test-faces C:/path/to/testfaces
```

Stop Sentinel Attend first: the pipeline test needs its ports.

| Prefix | Area | Type |
|---|---|---|
| HD | MFA (RFC 6238), password policy, setup codes, CSV safety, upload limits, media-server policy, repository secret scan | Cyber |
| CR | Encryption, vault, tamper/truncation/splice resistance | Cyber |
| AS | Anti-spoof model (port of suriAI/face-antispoof-onnx), gates, benchmark | Functional |
| FE | Recognition, blur irreversibility, selective unblur | Functional |
| LV | Liveness: photos, photo swaps, replays, screens, person swaps | Abuse |
| MT | Segmenter, transcode, watermark | Functional |
| PL | Real MediaMTX + privacy processor + encrypted recorder, end to end | Cyber |
| FN / AB / CY | The FastAPI application: first-run setup, invitations, resets, attendance, unblur, export; abuse and cyber cases | Functional / Abuse / Cyber |
| UI | Console per role, setup wizard, invitation and reset screens, XSS, CSP, kiosk, anti-spoof lab, keyboard, accessibility, responsive widths (needs Playwright) | Functional |

## Test faces (optional but recommended)

The `--test-faces` folder needs images of people who have agreed to it:

```
testfaces/
  enrol.jpg        one person, frontal, face >= 100 px
  group.jpg        a group photo that includes the enrol.jpg person, faces >= 40 px
  genuine/*.jpg    any photos of real people (>= 5 faces of >= 64 px in total)
```

Without the folder, face-image tests are reported as *Skipped*, never as passed.
Expected failures (`Known limitation`) document risks the system mitigates in other ways; see the report's risk table.

## Before every push

```
python scripts/secret_scan.py      # exit code 1 if anything secret-like is tracked
```

The same scan runs as test HD-14.
