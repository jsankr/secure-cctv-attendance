"""Synthetic presentation attacks used by the anti-spoof tests (digital approximations of physical attacks)."""
import numpy as np, cv2
rng = np.random.default_rng(7)
def frame_of(face_img, W=960, H=720, bg=(120,130,125)):
    f = np.full((H, W, 3), bg, np.uint8); h, w = face_img.shape[:2]; s = min(0.8*H/h, 0.8*W/w)
    r = cv2.resize(face_img, (int(w*s), int(h*s))); y, x = (H-r.shape[0])//2, (W-r.shape[1])//2
    f[y:y+r.shape[0], x:x+r.shape[1]] = r; return f
def print_attack(img):
    g = 40 + img.astype(np.float32) * 0.7
    yy, xx = np.mgrid[0:img.shape[0], 0:img.shape[1]]; dots = (np.sin(xx*1.9)*np.sin(yy*1.9)) * 18
    g = g + dots[..., None] + rng.normal(0, 6, g.shape); return cv2.GaussianBlur(np.clip(g,0,255).astype(np.uint8), (3,3), 0)
def screen_attack(img):
    up = cv2.resize(img, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST).astype(np.float32)
    mask = np.zeros_like(up); mask[:, 0::3, 2] = 1; mask[:, 1::3, 1] = 1; mask[:, 2::3, 0] = 1
    sub = cv2.resize(up * (0.35 + 0.65*mask), (img.shape[1], img.shape[0]), interpolation=cv2.INTER_AREA)
    yy, xx = np.mgrid[0:img.shape[0], 0:img.shape[1]]; moire = 14*np.sin((xx*0.37 + yy*0.11))
    glare = 60*np.exp(-(((xx-img.shape[1]*0.7)**2 + (yy-img.shape[0]*0.3)**2)/(2*(img.shape[1]*0.15)**2)))
    return np.clip(sub*1.1 + moire[..., None] + glare[..., None], 0, 255).astype(np.uint8)
def recapture_attack(img):
    s = cv2.resize(img, None, fx=0.35, fy=0.35, interpolation=cv2.INTER_AREA); s = cv2.resize(s, (img.shape[1], img.shape[0]))
    for q in (35, 50): s = cv2.imdecode(cv2.imencode(".jpg", s, [cv2.IMWRITE_JPEG_QUALITY, q])[1], 1)
    return s
def bezel_attack(img):
    h, w = img.shape[:2]; f = np.full((int(h*1.15), int(w*1.15), 3), 15, np.uint8); y, x = (f.shape[0]-h)//2, (f.shape[1]-w)//2
    f[y:y+h, x:x+w] = screen_attack(img); return cv2.resize(f, (w, h))
def dark(img): return (img.astype(np.float32) * 0.15).astype(np.uint8)
def backlit(img):
    f = frame_of(img, bg=(255,255,255)); return f
ATTACKS = {"print (halftone)": print_attack, "screen replay (sub-pixel+moire+glare)": screen_attack,
           "recapture (low-res+JPEG)": recapture_attack, "phone with bezel": bezel_attack}
