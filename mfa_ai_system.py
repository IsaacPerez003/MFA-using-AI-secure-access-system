from picamera2 import Picamera2
from picamera2.devices.imx500 import IMX500
import cv2
import numpy as np
import time
import os
import face_recognition
import lgpio
from mfrc522 import SimpleMFRC522
import threading
import queue
import csv
import json
import shutil
import subprocess
import re
from datetime import datetime
import tkinter as tk
from PIL import Image, ImageTk

MODEL = "/home/aas/face_rpk/network.rpk"
KNOWN_FACES_DIR = "/home/aas/known_faces"

SCORE_THRESH = 0.70
# Face-recognition security settings.
# Lower numbers are stricter. The previous 0.60 value was convenient for demos,
# but it can be too loose and may let a different person match the only enrolled user.
MATCH_THRESH = 0.48              # Best single saved face image must be this close or better
USER_AVG_MATCH_THRESH = 0.54     # Average of the closest saved images must also be close
GOOD_MATCH_THRESH = 0.56         # Saved images counted as supporting matches
MIN_GOOD_MATCHES_PER_USER = 3    # Require several saved images to agree
TOP_K_MATCHES = 3                # Use the closest K images for the average check

HOLD_SECONDS = 0.8
CROP_PAD_X = 0.20
CROP_PAD_Y = 0.25
REQUIRED_CONSEC_FRAMES = 8       # Require a more stable match before unlocking
MAX_MISSES = 10
UNLOCK_COOLDOWN = 10.0

MODEL_W = 640.0
MODEL_H = 640.0
PREVIEW_W = 640
PREVIEW_H = 480
PAD_Y = (MODEL_H - PREVIEW_H) / 2.0

LED_PIN = 12

# Relay signal pin connected to the relay module IN/SIG pin.
# GPIO23 is physical pin 16 on the Raspberry Pi header.
RELAY_PIN = 23

# Many relay modules are active LOW:
# GPIO LOW  = relay ON
# GPIO HIGH = relay OFF
# If your relay works the opposite way, change this to False.
RELAY_ACTIVE_LOW = False

# How long the 12V solenoid lock stays powered/unlocked.
UNLOCK_HOLD_TIME = 7.0

# Convert relay on/off state to the actual GPIO output level.
RELAY_ON_LEVEL = 0 if RELAY_ACTIVE_LOW else 1
RELAY_OFF_LEVEL = 1 if RELAY_ACTIVE_LOW else 0

# Initialize RFID first. On Raspberry Pi 5, SimpleMFRC522 uses the
# rpi-lgpio compatibility layer, and it should claim its reset pin before
# this program claims relay/LED GPIO lines directly with lgpio.
print("Initializing RFID reader...")
rfid_reader = SimpleMFRC522()
print("RFID reader initialized.")

# Initialize lgpio for LED and relay after RFID is initialized.
# On Raspberry Pi 5, the 40-pin header is commonly on gpiochip4.
# You can override this from Terminal with: RPI_LGPIO_CHIP=4
GPIO_CHIP = int(os.environ.get("RPI_LGPIO_CHIP", "4"))
h = lgpio.gpiochip_open(GPIO_CHIP)
lgpio.gpio_claim_output(h, LED_PIN, 0)

# Start relay OFF so the solenoid does not energize when the program starts.
lgpio.gpio_claim_output(h, RELAY_PIN, RELAY_OFF_LEVEL)

hardware_lock = threading.Lock()

JULIAN_ID = 1029237783851
ISAAC_ID = 788402240307

# Users are now loaded from a JSON database instead of only hardcoded IDs.
# The two old hardcoded IDs are used only to seed the database the first time.
DEFAULT_USERS = {
    str(JULIAN_ID): {"name": "Julian", "active": True},
    str(ISAAC_ID): {"name": "Isaac", "active": True},
}

SECURITY_DATA_DIR = "/home/aas/security_data"
USER_DB_FILE = os.path.join(SECURITY_DATA_DIR, "users.json")
DISABLED_FACES_DIR = os.path.join(SECURITY_DATA_DIR, "disabled_faces")

LOG_DIR = "/home/aas/security_logs"
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "access_events.csv")
USER_PROFILE_FILE = os.path.join(LOG_DIR, "user_access_profiles.json")

MIN_LOGINS_FOR_ANOMALY = 5
MIN_LOGINS_SAME_DAY = 3
ANOMALY_TIME_TOLERANCE_MIN = 90
SHOW_ANOMALY_ON_GUI = False

users_lock = threading.Lock()
audit_lock = threading.Lock()
admin_queue = queue.Queue()

# Admin/enrollment shared state. The RFID and camera are still controlled by this
# one main program, so separate programs do not fight over the same hardware.
admin_scan_mode = None
admin_pending_tag_id = None

enrollment_active = False
enrollment_name = ""
enrollment_tag_id = None
enrollment_save_dir = ""
enrollment_count = 0
enrollment_target_count = 18
# Slower interval gives the user time to slightly change angle/distance, which
# produces a better face database than 12 nearly identical photos.
enrollment_last_save_time = 0.0
enrollment_save_interval = 0.70
enrollment_last_det = None
enrollment_last_det_time = 0.0
ENROLLMENT_MIN_FACE_SIZE = 85
ENROLLMENT_MIN_BLUR = 18.0

rfid_verified_user = None
rfid_verified_tag_id = None
rfid_verified_time = 0
RFID_TIMEOUT = 15.0

# Only used as a small debounce so the same tag does not instantly scan multiple times
RFID_REPEAT_IGNORE_TIME = 1.5

# Prevent new RFID scans while the solenoid is unlocked
auth_busy_until = 0.0

# Add a small safety margin so RFID becomes active slightly after the relay turns off
BUSY_SAFETY_MARGIN = 0.5

# Sync RFID busy time with the full relay/solenoid unlock cycle:
# unlocked hold time + safety margin
AUTH_BUSY_TIME = UNLOCK_HOLD_TIME + BUSY_SAFETY_MARGIN

# GUI/security flow states. The camera feed is only displayed during FACE_AUTH.
STATE_IDLE = "IDLE"
STATE_WAIT_RFID = "WAIT_RFID"
STATE_FACE_AUTH = "FACE_AUTH"
STATE_SUCCESS = "SUCCESS"
STATE_DENIED = "DENIED"

WAIT_RFID_TIMEOUT = 20.0
RESULT_SCREEN_TIME = 3.0

state_lock = threading.Lock()
system_state = STATE_IDLE
state_message = "Slide to begin"
state_until = 0.0

event_log = queue.Queue()
gui = None

imx500 = IMX500(MODEL)
picam2 = Picamera2()

config = picam2.create_preview_configuration(
    main={"size": (PREVIEW_W, PREVIEW_H), "format": "RGB888"},
    controls={"FrameRate": 30},
    buffer_count=12,
)
picam2.configure(config)

known_names = []
known_encodings = []
known_faces_lock = threading.Lock()
faces_reload_lock = threading.Lock()
faces_reload_running = False


def load_known_faces():
    """
    Load face encodings from disk.

    Important: build the new database in local lists first, then swap it in at
    the end. That prevents the authentication loop from seeing a half-loaded
    face database while an admin reload is running.
    """
    global known_names, known_encodings

    new_names = []
    new_encodings = []

    if not os.path.isdir(KNOWN_FACES_DIR):
        print("Known faces folder not found:", KNOWN_FACES_DIR)
        return

    for person_name in sorted(os.listdir(KNOWN_FACES_DIR)):
        person_dir = os.path.join(KNOWN_FACES_DIR, person_name)

        if not os.path.isdir(person_dir):
            continue

        for fname in sorted(os.listdir(person_dir)):
            fpath = os.path.join(person_dir, fname)

            try:
                image = face_recognition.load_image_file(fpath)
                encs = face_recognition.face_encodings(
                    image,
                    num_jitters=2,
                    model="small"
                )

                if len(encs) > 0:
                    new_names.append(person_name)
                    new_encodings.append(encs[0])
                    print("Loaded:", person_name, fname)
                else:
                    print("No face in:", fpath)

            except Exception as e:
                print("Failed:", fpath, e)

    with known_faces_lock:
        known_names = new_names
        known_encodings = new_encodings

    print("Total encodings:", len(new_encodings))


def reload_known_faces_async(reason=""):
    """Reload face encodings in a background thread so the GUI does not freeze."""
    global faces_reload_running

    with faces_reload_lock:
        if faces_reload_running:
            admin_event("Face database reload is already running. Please wait.")
            return False
        faces_reload_running = True

    def worker():
        global faces_reload_running
        try:
            if reason:
                admin_event(f"Reloading face database in background: {reason}")
            else:
                admin_event("Reloading face database in background...")

            load_known_faces()
            admin_event(f"Face database reload complete. Encodings loaded: {len(known_encodings)}")

            if gui is not None:
                try:
                    gui.root.after(0, gui.refresh_admin_users)
                    gui.root.after(0, lambda: gui.admin_status.configure(
                        text=f"Face database reload complete. Encodings loaded: {len(known_encodings)}"
                    ))
                except Exception:
                    pass

        except Exception as e:
            admin_event(f"Face database reload error: {e}")
        finally:
            with faces_reload_lock:
                faces_reload_running = False

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return True


def led_on():
    lgpio.gpio_write(h, LED_PIN, 1)


def led_off():
    lgpio.gpio_write(h, LED_PIN, 0)


def relay_on():
    lgpio.gpio_write(h, RELAY_PIN, RELAY_ON_LEVEL)


def relay_off():
    lgpio.gpio_write(h, RELAY_PIN, RELAY_OFF_LEVEL)


def unlock_hardware(name):
    # Prevent two unlock threads from controlling the relay at the same time.
    if not hardware_lock.acquire(blocking=False):
        log_event("Relay already active; ignoring duplicate unlock")
        return

    try:
        log_event(f"UNLOCKING FOR: {name}")
        led_off()

        # Energize the relay. This connects COM to NO and powers the 12V solenoid.
        relay_on()

        # Keep the lock powered/unlocked for the selected time.
        time.sleep(UNLOCK_HOLD_TIME)

    finally:
        # Always turn the relay off, even if an error occurs.
        relay_off()
        hardware_lock.release()


def deny_and_reset():
    led_off()
    relay_off()


def rfid_loop():
    global rfid_verified_user, rfid_verified_tag_id, rfid_verified_time, auth_busy_until
    global admin_scan_mode, admin_pending_tag_id

    last_tag_id = None
    last_read_time = 0.0

    while True:
        try:
            # Public RFID scans only happen on the ID-scan screen. Admin RFID
            # scans can happen from the HDMI admin window while system is idle.
            if admin_scan_mode != "enroll" and get_system_state()[0] != STATE_WAIT_RFID:
                time.sleep(0.1)
                continue

            tag_id = rfid_reader.read_id()
            now = time.time()

            if admin_scan_mode == "enroll":
                admin_pending_tag_id = tag_id
                admin_scan_mode = None
                admin_event(f"Admin captured RFID tag: {tag_id}")
                record_audit_event(
                    event_type="admin_rfid_scan",
                    tag_id=tag_id,
                    outcome="captured",
                    reason="admin enrollment RFID scan",
                )
                time.sleep(0.5)
                continue

            # If the GUI moved away from the scan screen while the RFID call was
            # blocking, ignore whatever was just read.
            if get_system_state()[0] != STATE_WAIT_RFID:
                time.sleep(0.1)
                continue

            # If the system recently unlocked, ignore RFID scans for a while.
            if now < auth_busy_until:
                time.sleep(0.3)
                continue

            # Ignore repeated reads of the same card for a short time.
            if tag_id == last_tag_id and (now - last_read_time) < RFID_REPEAT_IGNORE_TIME:
                time.sleep(0.3)
                continue

            last_tag_id = tag_id
            last_read_time = now

            log_event(f"RFID tag read: {tag_id}")

            user_name, active = lookup_user_by_tag(tag_id)

            if user_name and active:
                rfid_verified_user = user_name
                rfid_verified_tag_id = tag_id
                rfid_verified_time = now
                led_on()
                set_system_state(STATE_FACE_AUTH, "ID accepted. Face the camera.", now + RFID_TIMEOUT)
                log_event(f"RFID: {user_name} scanned")
                record_audit_event(
                    event_type="rfid_accepted",
                    user=user_name,
                    tag_id=tag_id,
                    outcome="accepted",
                    reason="active registered RFID tag",
                )

            elif user_name and not active:
                rfid_verified_user = None
                rfid_verified_tag_id = None
                rfid_verified_time = 0.0
                deny_and_reset()
                set_system_state(STATE_DENIED, "ID disabled", now + RESULT_SCREEN_TIME)
                log_event(f"RFID disabled user scanned: {user_name}")
                record_audit_event(
                    event_type="rfid_disabled",
                    user=user_name,
                    tag_id=tag_id,
                    outcome="denied",
                    reason="disabled user RFID tag",
                )

            else:
                rfid_verified_user = None
                rfid_verified_tag_id = None
                rfid_verified_time = 0.0
                deny_and_reset()
                set_system_state(STATE_DENIED, "Invalid ID tag", now + RESULT_SCREEN_TIME)
                log_event("RFID: Unknown tag")
                record_audit_event(
                    event_type="rfid_unknown",
                    tag_id=tag_id,
                    outcome="denied",
                    reason="unknown RFID tag",
                )

            time.sleep(0.5)

        except Exception as e:
            log_event(f"RFID error: {e}")
            time.sleep(0.5)

def decode_outputs(metadata):
    outputs = imx500.get_outputs(metadata, add_batch=True)

    if outputs is None or len(outputs) < 4:
        return None, None

    boxes = np.array(outputs[0]).reshape(-1, 4).astype(np.float32)
    scores = np.array(outputs[1]).reshape(-1).astype(np.float32)
    classes = np.array(outputs[2]).reshape(-1).astype(np.float32)
    count_raw = np.array(outputs[3]).reshape(-1).astype(np.float32)

    count = int(count_raw[0]) if len(count_raw) else 0
    count = max(0, min(count, len(scores), len(boxes), len(classes)))

    dets = []

    for i in range(count):
        score = float(scores[i])
        cls = int(classes[i])
        x1, y1, x2, y2 = boxes[i].tolist()

        dets.append({
            "score": score,
            "class": cls,
            "box": [x1, y1, x2, y2]
        })

    info = {
        "count_raw": count_raw.tolist(),
        "count_used": count,
        "score_max": float(scores.max()) if len(scores) else None,
        "top5_scores": sorted([float(s) for s in scores], reverse=True)[:5],
    }

    return dets, info


def clamp_box(x1, y1, x2, y2, w, h):
    x1 = max(0, min(w - 1, int(round(x1))))
    x2 = max(0, min(w - 1, int(round(x2))))
    y1 = max(0, min(h - 1, int(round(y1))))
    y2 = max(0, min(h - 1, int(round(y2))))

    return x1, y1, x2, y2


def model_to_preview_box(x1, y1, x2, y2, preview_w, preview_h):
    if max(abs(x1), abs(y1), abs(x2), abs(y2)) <= 2.0:
        x1 *= MODEL_W
        x2 *= MODEL_W
        y1 *= MODEL_H
        y2 *= MODEL_H

    y1 -= PAD_Y
    y2 -= PAD_Y

    return clamp_box(x1, y1, x2, y2, preview_w, preview_h)


def make_padded_crop(frame, x1, y1, x2, y2, pad_x_frac=CROP_PAD_X, pad_y_frac=CROP_PAD_Y):
    fh, fw = frame.shape[:2]

    bw = x2 - x1
    bh = y2 - y1

    if bw <= 0 or bh <= 0:
        return None, None

    pad_x = int(bw * pad_x_frac)
    pad_y = int(bh * pad_y_frac)

    x1p = max(0, x1 - pad_x)
    y1p = max(0, y1 - pad_y)
    x2p = min(fw, x2 + pad_x)
    y2p = min(fh, y2 + pad_y)

    if x2p <= x1p or y2p <= y1p:
        return None, None

    face_crop = frame[y1p:y2p, x1p:x2p].copy()

    top = y1 - y1p
    right = x2 - x1p
    bottom = y2 - y1p
    left = x1 - x1p

    crop_h, crop_w = face_crop.shape[:2]

    top = max(0, min(crop_h - 1, top))
    bottom = max(0, min(crop_h - 1, bottom))
    left = max(0, min(crop_w - 1, left))
    right = max(0, min(crop_w - 1, right))

    if bottom <= top or right <= left:
        return None, None

    return face_crop, (top, right, bottom, left)


def recognize_face(face_rgb, known_face_location=None):
    with known_faces_lock:
        local_names = list(known_names)
        local_encodings = list(known_encodings)

    if len(local_encodings) == 0:
        return "Unknown", None

    if face_rgb is None or face_rgb.size == 0:
        return "Unknown", None

    face_rgb = np.ascontiguousarray(np.asarray(face_rgb, dtype=np.uint8))

    if face_rgb.ndim != 3 or face_rgb.shape[2] != 3:
        return "Unknown", None

    fh, fw = face_rgb.shape[:2]

    if fh < 40 or fw < 40:
        return "Unknown", None

    try:
        if known_face_location is not None:
            encs = face_recognition.face_encodings(
                face_rgb,
                known_face_locations=[known_face_location],
                num_jitters=2,
                model="small"
            )
        else:
            encs = face_recognition.face_encodings(
                face_rgb,
                num_jitters=2,
                model="small"
            )

    except Exception as e:
        print("Recognition error:", e)
        return "Unknown", None

    if len(encs) == 0:
        return "Unknown", None

    face_enc = encs[0]
    distances = face_recognition.face_distance(local_encodings, face_enc)

    # More secure than simply accepting the closest single image:
    # group all saved encodings by user and require several of that user's
    # saved images to agree with the live face.
    best_candidate = None

    for user_name in sorted(set(local_names)):
        user_dists = [float(distances[i]) for i, n in enumerate(local_names) if n == user_name]
        if not user_dists:
            continue

        user_dists.sort()
        top_k = user_dists[:min(TOP_K_MATCHES, len(user_dists))]
        best_dist = user_dists[0]
        avg_top_dist = sum(top_k) / len(top_k)
        good_count = sum(1 for d in user_dists if d <= GOOD_MATCH_THRESH)
        required_good = min(MIN_GOOD_MATCHES_PER_USER, len(user_dists))

        candidate = {
            "name": user_name,
            "best_dist": best_dist,
            "avg_top_dist": avg_top_dist,
            "good_count": good_count,
            "required_good": required_good,
            "total_images": len(user_dists),
        }

        if best_candidate is None or candidate["avg_top_dist"] < best_candidate["avg_top_dist"]:
            best_candidate = candidate

    if best_candidate is None:
        return "Unknown", None

    passed = (
        best_candidate["best_dist"] <= MATCH_THRESH
        and best_candidate["avg_top_dist"] <= USER_AVG_MATCH_THRESH
        and best_candidate["good_count"] >= best_candidate["required_good"]
    )

    # Return the average-top distance because it is a better security signal than
    # one lucky/bad saved photo matching by itself.
    reported_dist = best_candidate["avg_top_dist"]

    if passed:
        return best_candidate["name"], reported_dist

    return "Unknown", reported_dist


def draw_detection(frame, det, label_text="", color=(0, 255, 0)):
    # SECURITY/CLEAN DISPLAY MODE:
    # Draw the face box only. Do not draw the detected name, RFID status,
    # lock state, FPS, or authentication text on top of the camera feed.
    # The recognition/authentication logic still uses det["name"] internally.
    x1, y1, x2, y2 = det["preview_box"]
    cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)


def log_event(message):
    """Print message and send it to the GUI event log safely."""
    line = f"{time.strftime('%H:%M:%S')}  {message}"
    print(message)
    event_log.put(line)


def admin_event(message):
    """Send message to admin/control-panel log safely."""
    line = f"{time.strftime('%H:%M:%S')}  {message}"
    print("ADMIN:", message)
    admin_queue.put(line)


def ensure_security_dirs():
    os.makedirs(SECURITY_DATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(KNOWN_FACES_DIR, exist_ok=True)
    os.makedirs(DISABLED_FACES_DIR, exist_ok=True)


def ensure_user_db():
    ensure_security_dirs()
    if not os.path.isfile(USER_DB_FILE):
        with users_lock:
            with open(USER_DB_FILE, "w") as f:
                json.dump(DEFAULT_USERS, f, indent=2)
        admin_event(f"Created user database: {USER_DB_FILE}")


def load_users():
    ensure_user_db()
    with users_lock:
        try:
            with open(USER_DB_FILE, "r") as f:
                data = json.load(f)
        except Exception as e:
            admin_event(f"Could not load users.json: {e}")
            return {}

    # Normalize fields.
    clean = {}
    for tag_id, info in data.items():
        if isinstance(info, str):
            clean[str(tag_id)] = {"name": info, "active": True}
        elif isinstance(info, dict):
            clean[str(tag_id)] = {
                "name": str(info.get("name", "Unknown")),
                "active": bool(info.get("active", True)),
            }
    return clean


def save_users(users):
    ensure_security_dirs()
    with users_lock:
        with open(USER_DB_FILE, "w") as f:
            json.dump(users, f, indent=2)


def lookup_user_by_tag(tag_id):
    users = load_users()
    info = users.get(str(tag_id))
    if not info:
        return None, False
    return info.get("name"), bool(info.get("active", True))


def add_or_update_user(tag_id, name, active=True):
    users = load_users()
    users[str(tag_id)] = {"name": name.strip(), "active": bool(active)}
    save_users(users)
    admin_event(f"Saved user: {name} tag={tag_id} active={active}")


def set_user_active(tag_id, active):
    users = load_users()
    tag_id = str(tag_id)
    if tag_id in users:
        users[tag_id]["active"] = bool(active)
        save_users(users)
        admin_event(f"Set {users[tag_id]['name']} active={active}")
        return True
    return False


def remove_user(tag_id, archive_faces=True):
    users = load_users()
    tag_id = str(tag_id)
    info = users.pop(tag_id, None)
    if not info:
        return False

    name = info.get("name", "Unknown")
    save_users(users)

    if archive_faces:
        face_dir = os.path.join(KNOWN_FACES_DIR, name)
        if os.path.isdir(face_dir):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_dir = os.path.join(DISABLED_FACES_DIR, f"{name}_{tag_id}_{ts}")
            try:
                shutil.move(face_dir, archive_dir)
                admin_event(f"Archived face folder to: {archive_dir}")
            except Exception as e:
                admin_event(f"Could not archive face folder: {e}")

    admin_event(f"Removed user: {name} tag={tag_id}")
    return True


def sanitize_person_name(name):
    safe = "".join(c for c in name.strip() if c.isalnum() or c in (" ", "_", "-")).strip()
    return safe.replace("/", "_")


def start_admin_rfid_scan():
    global admin_scan_mode, admin_pending_tag_id
    if get_system_state()[0] != STATE_IDLE:
        admin_event("Cannot scan admin RFID while public authentication is active.")
        return False
    admin_pending_tag_id = None
    admin_scan_mode = "enroll"
    admin_event("Waiting for new user's RFID card scan...")
    return True


def start_face_enrollment(name, tag_id, target_count=18):
    global enrollment_active, enrollment_name, enrollment_tag_id, enrollment_save_dir
    global enrollment_count, enrollment_target_count, enrollment_last_save_time
    global enrollment_last_det, enrollment_last_det_time

    clean_name = sanitize_person_name(name)
    if not clean_name:
        admin_event("Enrollment failed: no valid name.")
        return False
    if tag_id is None or str(tag_id).strip() == "":
        admin_event("Enrollment failed: no RFID tag ID.")
        return False
    if get_system_state()[0] != STATE_IDLE:
        admin_event("Enrollment failed: public authentication is active.")
        return False

    enrollment_name = clean_name
    enrollment_tag_id = str(tag_id).strip()
    enrollment_save_dir = os.path.join(KNOWN_FACES_DIR, clean_name)
    os.makedirs(enrollment_save_dir, exist_ok=True)
    enrollment_count = 0
    enrollment_target_count = int(target_count)
    enrollment_last_save_time = 0.0
    enrollment_last_det = None
    enrollment_last_det_time = 0.0
    enrollment_active = True

    record_audit_event(
        event_type="enrollment_started",
        user=clean_name,
        tag_id=enrollment_tag_id,
        outcome="started",
        reason="admin started face enrollment",
    )
    admin_event(f"Enrollment started for {clean_name}. Slowly move head left/right and closer/farther while looking at camera.")
    return True


def stop_face_enrollment(cancelled=True):
    global enrollment_active
    if enrollment_active and cancelled:
        admin_event("Enrollment cancelled.")
    enrollment_active = False


def enrollment_image_quality_ok(face_crop):
    """Reject blurry/tiny crops before they enter the face database."""
    if face_crop is None or face_crop.size <= 0:
        return False, "empty crop"

    h, w = face_crop.shape[:2]
    if h < ENROLLMENT_MIN_FACE_SIZE or w < ENROLLMENT_MIN_FACE_SIZE:
        return False, f"face crop too small ({w}x{h})"

    gray = cv2.cvtColor(face_crop, cv2.COLOR_RGB2GRAY)
    blur_score = cv2.Laplacian(gray, cv2.CV_64F).var()
    if blur_score < ENROLLMENT_MIN_BLUR:
        return False, f"image blurry, score={blur_score:.1f}"

    return True, f"quality ok, blur={blur_score:.1f}"


def save_enrollment_face(frame, det):
    global enrollment_count, enrollment_last_save_time, enrollment_active

    x1, y1, x2, y2 = det["preview_box"]

    # Save the same kind of padded face crop that the recognizer uses later.
    # The previous version saved a tight AI-detection box, which sometimes cut
    # off useful face context and caused inconsistent recognition.
    face_crop, known_face_location = make_padded_crop(frame, x1, y1, x2, y2)
    ok, quality_msg = enrollment_image_quality_ok(face_crop)
    if not ok:
        # Update the timer slightly so this does not spam the admin log every frame.
        enrollment_last_save_time = time.time() - max(0.0, enrollment_save_interval - 0.25)
        admin_event(f"Enrollment image skipped: {quality_msg}")
        return

    try:
        face_crop = np.ascontiguousarray(np.asarray(face_crop, dtype=np.uint8))
        encs = face_recognition.face_encodings(
            face_crop,
            known_face_locations=[known_face_location],
            num_jitters=2,
            model="small"
        )
    except Exception as e:
        encs = []
        admin_event(f"Enrollment image skipped: encoding error: {e}")

    if len(encs) == 0:
        enrollment_last_save_time = time.time() - max(0.0, enrollment_save_interval - 0.25)
        admin_event("Enrollment image skipped: face encoding failed")
        return

    enrollment_count += 1
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"face_{timestamp}_{enrollment_count:03d}.jpg"
    save_path = os.path.join(enrollment_save_dir, filename)
    cv2.imwrite(save_path, cv2.cvtColor(face_crop, cv2.COLOR_RGB2BGR))
    enrollment_last_save_time = time.time()
    admin_event(
        f"Saved enrollment image {enrollment_count}/{enrollment_target_count}: "
        f"{filename} ({quality_msg})"
    )

    if enrollment_count >= enrollment_target_count:
        completed_name = enrollment_name
        add_or_update_user(enrollment_tag_id, completed_name, active=True)
        record_audit_event(
            event_type="enrollment_completed",
            user=completed_name,
            tag_id=enrollment_tag_id,
            outcome="completed",
            reason=f"captured {enrollment_count} quality-checked face images",
        )
        enrollment_active = False
        admin_event(f"Enrollment complete for {completed_name}. User added. Reloading face database in background...")
        reload_known_faces_async(reason=f"new user {completed_name}")


def process_enrollment_frame(frame, metadata, now):
    global enrollment_last_det, enrollment_last_det_time

    if not enrollment_active:
        return frame

    dets, info = decode_outputs(metadata)
    strong = []

    if dets:
        for d in dets:
            if d["score"] >= SCORE_THRESH and d["class"] == 0:
                px1, py1, px2, py2 = model_to_preview_box(*d["box"], PREVIEW_W, PREVIEW_H)
                if px2 > px1 and py2 > py1:
                    d["preview_box"] = [px1, py1, px2, py2]
                    strong.append(d)

    chosen = None
    if strong:
        strong.sort(key=lambda x: x["score"], reverse=True)
        chosen = strong[0]
        enrollment_last_det = chosen
        enrollment_last_det_time = now
    elif enrollment_last_det and (now - enrollment_last_det_time) < HOLD_SECONDS:
        chosen = enrollment_last_det

    if chosen:
        draw_detection(frame, chosen, color=(0, 255, 0))
        if now - enrollment_last_save_time >= enrollment_save_interval:
            save_enrollment_face(frame, chosen)
    else:
        cv2.putText(
            frame,
            "Enrollment: face not detected",
            (10, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (255, 0, 0),
            2,
            cv2.LINE_AA,
        )

    return frame


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def minutes_from_midnight(dt):
    return dt.hour * 60 + dt.minute + (dt.second / 60.0)


def circular_minute_distance(a, b):
    diff = abs(float(a) - float(b)) % 1440
    return min(diff, 1440 - diff)


def circular_mean_minutes(values):
    if not values:
        return 0.0
    angles = [(float(v) / 1440.0) * 2.0 * np.pi for v in values]
    sin_sum = sum(np.sin(a) for a in angles)
    cos_sum = sum(np.cos(a) for a in angles)
    if abs(sin_sum) < 1e-9 and abs(cos_sum) < 1e-9:
        return float(sum(values)) / len(values)
    avg_angle = np.arctan2(sin_sum, cos_sum)
    if avg_angle < 0:
        avg_angle += 2.0 * np.pi
    return (avg_angle / (2.0 * np.pi)) * 1440.0


def minutes_to_hhmm(minutes):
    minutes = int(round(minutes)) % 1440
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def record_audit_event(event_type, user="", tag_id="", outcome="", reason="", anomaly_flag=False, anomaly_score=0.0, details=""):
    ensure_log_dir()
    now_dt = datetime.now().astimezone()
    row = {
        "timestamp": now_dt.isoformat(timespec="seconds"),
        "date": now_dt.strftime("%Y-%m-%d"),
        "time": now_dt.strftime("%H:%M:%S"),
        "weekday": now_dt.strftime("%A"),
        "hour": now_dt.hour,
        "minute_of_day": round(minutes_from_midnight(now_dt), 2),
        "user": user or "",
        "tag_id": str(tag_id) if tag_id is not None else "",
        "event_type": event_type,
        "outcome": outcome,
        "reason": reason,
        "anomaly_flag": "YES" if anomaly_flag else "NO",
        "anomaly_score": round(float(anomaly_score), 3),
        "details": details,
    }
    fieldnames = list(row.keys())
    with audit_lock:
        file_exists = os.path.isfile(AUDIT_LOG_FILE)
        with open(AUDIT_LOG_FILE, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)


def read_successful_access_history(user):
    if not os.path.isfile(AUDIT_LOG_FILE):
        return []
    history = []
    try:
        with audit_lock:
            with open(AUDIT_LOG_FILE, "r", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("event_type") != "access_granted" or row.get("outcome") != "granted":
                        continue
                    if row.get("user") != user:
                        continue
                    try:
                        dt = datetime.fromisoformat(row["timestamp"])
                    except Exception:
                        continue
                    history.append({
                        "timestamp": dt,
                        "weekday": dt.weekday(),
                        "minute_of_day": minutes_from_midnight(dt),
                    })
    except Exception as e:
        log_event(f"Audit history read error: {e}")
    return history


def build_user_profiles():
    ensure_log_dir()
    profiles = {}
    if not os.path.isfile(AUDIT_LOG_FILE):
        return profiles
    try:
        with audit_lock:
            with open(AUDIT_LOG_FILE, "r", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("event_type") != "access_granted" or row.get("outcome") != "granted":
                        continue
                    user = row.get("user", "")
                    if not user:
                        continue
                    try:
                        dt = datetime.fromisoformat(row["timestamp"])
                    except Exception:
                        continue
                    profile = profiles.setdefault(user, {"total_successful_accesses": 0, "days": {}})
                    profile["total_successful_accesses"] += 1
                    day_name = dt.strftime("%A")
                    profile["days"].setdefault(day_name, []).append(minutes_from_midnight(dt))
        for user, profile in profiles.items():
            for day_name, values in list(profile["days"].items()):
                profile["days"][day_name] = {
                    "count": len(values),
                    "typical_time": minutes_to_hhmm(circular_mean_minutes(values)),
                }
        with open(USER_PROFILE_FILE, "w") as f:
            json.dump(profiles, f, indent=2)
    except Exception as e:
        log_event(f"Profile build error: {e}")
    return profiles


def evaluate_login_anomaly(user, when=None):
    when = when or datetime.now().astimezone()
    history = read_successful_access_history(user)
    if len(history) < MIN_LOGINS_FOR_ANOMALY:
        return {"flag": False, "score": 0.0, "reason": f"learning mode: {len(history)} prior successful login(s)"}
    current_min = minutes_from_midnight(when)
    same_day = [h for h in history if h["weekday"] == when.weekday()]
    if len(same_day) >= MIN_LOGINS_SAME_DAY:
        baseline_values = [h["minute_of_day"] for h in same_day]
        baseline_source = f"same weekday ({when.strftime('%A')})"
    else:
        baseline_values = [h["minute_of_day"] for h in history]
        baseline_source = "all days"
    typical_min = circular_mean_minutes(baseline_values)
    diff_min = circular_minute_distance(current_min, typical_min)
    score = diff_min / float(ANOMALY_TIME_TOLERANCE_MIN)
    flag = diff_min > ANOMALY_TIME_TOLERANCE_MIN
    reason = (
        f"current={minutes_to_hhmm(current_min)}, "
        f"typical={minutes_to_hhmm(typical_min)} based on {baseline_source}, "
        f"difference={int(round(diff_min))} min"
    )
    return {"flag": flag, "score": score, "reason": reason}


def set_system_state(new_state, message="", until=0.0):
    global system_state, state_message, state_until
    with state_lock:
        system_state = new_state
        state_message = message
        state_until = until


def get_system_state():
    with state_lock:
        return system_state, state_message, state_until


# ---------- GUI THEME ----------
# Change colors/fonts here and the whole interface updates.
THEME = {
    "bg": "#07111f",              # main background: deep navy
    "card": "#0f1b2d",            # main panel/card
    "panel": "#13243a",           # message panel
    "panel_alt": "#102a45",       # RFID/wait panel
    "camera": "#000000",
    "text": "#f5f7fb",
    "muted": "#9fb0c7",
    "accent": "#28d7ff",          # cyan accent
    "accent_dark": "#0a6c84",
    "success": "#087f3b",         # green
    "success_dark": "#053d20",
    "danger": "#9d1c2b",          # red
    "danger_dark": "#4d0b14",
    "warning": "#ffcc4d",
    "button": "#1c3554",
    "button_hover": "#28496f",
    "button_text": "#ffffff",
    "log_bg": "#06101d",
}

FONT_FAMILY = "DejaVu Sans"
FONT_TITLE = (FONT_FAMILY, 20, "bold")
FONT_HERO = (FONT_FAMILY, 26, "bold")
FONT_SUB = (FONT_FAMILY, 12)
FONT_STATUS = (FONT_FAMILY, 10, "bold")
FONT_SMALL = (FONT_FAMILY, 9)
FONT_BUTTON = (FONT_FAMILY, 10, "bold")
FONT_LOG = ("DejaVu Sans Mono", 9)

# Set to True while debugging. For a public-facing door screen, False looks cleaner.
SHOW_SERVICE_LOG = False

# Optional full-window background image.
# The program will try these paths in order and use the first one it finds.
# Linux file names are case-sensitive, so Security_Background.png is different
# from security_background.png.
USE_BACKGROUND_IMAGE = False
BACKGROUND_IMAGE = "/home/aas/Downloads/security_background.png"
BACKGROUND_IMAGE_CANDIDATES = [
    BACKGROUND_IMAGE,
    "/home/aas/Downloads/security_background.jpg",
    "/home/aas/Downloads/security_background.jpeg",
    "/home/aas/Downloads/background.png",
    "/home/aas/Downloads/background.jpg",
    "/home/aas/Downloads/background.jpeg",
]
BACKGROUND_DIM_OVERLAY = 0.35  # 0.0 = no dim, 1.0 = fully black
CARD_MARGIN_X = 28
CARD_MARGIN_Y = 18

# ---------- DISPLAY / KIOSK SETTINGS ----------
# The public Secure Access screen should be locked to the touchscreen.
# The admin/control panel should open on the HDMI monitor.
#
# Auto-detect uses xrandr. You can override from Terminal if needed, for example:
# MFA_PUBLIC_GEOMETRY="800x480+1920+0" MFA_ADMIN_GEOMETRY="1200x700+0+0" \
# RPI_LGPIO_CHIP=4 python3 mfa_rfid_face_relay_gui_admin_enrollment_kiosk.py
PUBLIC_KIOSK_MODE = True
PUBLIC_HIDE_CURSOR = True
PUBLIC_DISPLAY_PREFERENCE = os.environ.get("MFA_PUBLIC_DISPLAY", "DSI")
ADMIN_DISPLAY_PREFERENCE = os.environ.get("MFA_ADMIN_DISPLAY", "HDMI")
PUBLIC_GEOMETRY_OVERRIDE = os.environ.get("MFA_PUBLIC_GEOMETRY", "")
ADMIN_GEOMETRY_OVERRIDE = os.environ.get("MFA_ADMIN_GEOMETRY", "")
DEFAULT_PUBLIC_GEOMETRY = "800x480+0+0"
DEFAULT_ADMIN_GEOMETRY = "1000x700+800+0"


def blend_hex(c1, c2, t):
    """Blend two #RRGGBB colors. t=0 returns c1, t=1 returns c2."""
    c1 = c1.lstrip('#')
    c2 = c2.lstrip('#')
    r1, g1, b1 = int(c1[0:2], 16), int(c1[2:4], 16), int(c1[4:6], 16)
    r2, g2, b2 = int(c2[0:2], 16), int(c2[2:4], 16), int(c2[4:6], 16)
    r = int(r1 + (r2 - r1) * t)
    g = int(g1 + (g2 - g1) * t)
    b = int(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def cover_resize(image, target_w, target_h):
    """Resize/crop image to cover the target area without distortion."""
    if target_w <= 1 or target_h <= 1:
        return image

    src_w, src_h = image.size
    scale = max(target_w / src_w, target_h / src_h)
    new_w = int(src_w * scale)
    new_h = int(src_h * scale)
    resized = image.resize((new_w, new_h), Image.LANCZOS)

    left = max(0, (new_w - target_w) // 2)
    top = max(0, (new_h - target_h) // 2)
    return resized.crop((left, top, left + target_w, top + target_h))


def dim_image(image, amount):
    """Darken image so white UI text remains readable."""
    amount = max(0.0, min(1.0, float(amount)))
    if amount <= 0:
        return image

    black = Image.new("RGB", image.size, (0, 0, 0))
    return Image.blend(image, black, amount)


def parse_xrandr_monitors():
    """Return connected monitors from xrandr as dictionaries."""
    monitors = []

    try:
        output = subprocess.check_output(
            ["xrandr", "--query"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print("Could not run xrandr monitor detection:", e)
        return monitors

    pattern = re.compile(
        r"^(\S+)\s+connected(?:\s+primary)?\s+(\d+)x(\d+)\+(-?\d+)\+(-?\d+)"
    )

    for line in output.splitlines():
        match = pattern.search(line)
        if not match:
            continue

        name, w, h, x, y = match.groups()
        monitors.append({
            "name": name,
            "w": int(w),
            "h": int(h),
            "x": int(x),
            "y": int(y),
        })

    print("Detected monitors:", monitors)
    return monitors


def geometry_from_monitor(monitor, default_geometry):
    if not monitor:
        return default_geometry
    return f"{monitor['w']}x{monitor['h']}+{monitor['x']}+{monitor['y']}"


def choose_public_and_admin_geometries():
    public_geometry = PUBLIC_GEOMETRY_OVERRIDE or None
    admin_geometry = ADMIN_GEOMETRY_OVERRIDE or None

    monitors = parse_xrandr_monitors()

    public_monitor = None
    admin_monitor = None

    if monitors:
        pref = PUBLIC_DISPLAY_PREFERENCE.lower()
        for m in monitors:
            if pref and pref in m["name"].lower():
                public_monitor = m
                break

        if public_monitor is None:
            public_monitor = min(monitors, key=lambda m: m["w"] * m["h"])

        pref = ADMIN_DISPLAY_PREFERENCE.lower()
        for m in monitors:
            if m is public_monitor:
                continue
            if pref and pref in m["name"].lower():
                admin_monitor = m
                break

        if admin_monitor is None:
            others = [m for m in monitors if m is not public_monitor]
            admin_monitor = max(others, key=lambda m: m["w"] * m["h"]) if others else None

    if public_geometry is None:
        public_geometry = geometry_from_monitor(public_monitor, DEFAULT_PUBLIC_GEOMETRY)

    if admin_geometry is None:
        admin_geometry = geometry_from_monitor(admin_monitor, DEFAULT_ADMIN_GEOMETRY)

    print("Public Secure Access geometry:", public_geometry)
    print("Admin Control Panel geometry:", admin_geometry)
    return public_geometry, admin_geometry



class MFAInteractiveGUI:
    def __init__(self):
        self.running = True
        self.image_ref = None
        self.current_screen = None
        self.fullscreen = True
        self.spinner_index = 0
        self.bg_original = None
        self.bg_photo = None
        self.last_bg_size = None
        self.spinner_chars = ["●○○", "○●○", "○○●", "○●○"]
        self.slider_frame = None
        self.slider = None
        self.slider_hint = None

        self.public_geometry, self.admin_geometry = choose_public_and_admin_geometries()

        self.root = tk.Tk()
        self.slider_var = tk.IntVar(master=self.root, value=0)
        self.root.title("Secure Access")
        self.root.geometry(self.public_geometry)
        self.root.configure(bg=THEME["bg"])

        if PUBLIC_KIOSK_MODE:
            # Kiosk mode for the public touchscreen: no window border, no close
            # button, no Escape/q quit shortcut, and no mouse cursor. This does
            # not stop someone with shell access or power access, but it prevents
            # normal users from closing the public GUI from the touchscreen.
            self.root.protocol("WM_DELETE_WINDOW", lambda: None)
            self.root.overrideredirect(True)
            self.root.resizable(False, False)
            self.root.attributes("-topmost", True)
            if PUBLIC_HIDE_CURSOR:
                self.root.configure(cursor="none")
            self.root.bind("<Alt-F4>", lambda event: "break")
            self.root.bind("<Escape>", lambda event: "break")
            self.root.bind("q", lambda event: "break")
            self.root.bind("<F11>", lambda event: "break")
            self.root.after(500, lambda: self.root.geometry(self.public_geometry))
        else:
            self.root.protocol("WM_DELETE_WINDOW", self.request_quit)
            self.root.bind("<Escape>", lambda event: self.request_quit())
            self.root.bind("q", lambda event: self.request_quit())
            self.root.bind("<F11>", lambda event: self.toggle_fullscreen())
            self.root.attributes("-fullscreen", self.fullscreen)

        self.root.update_idletasks()

        # Optional full-window background image. The solid card stays on top so the
        # interface remains readable and professional.
        self.bg_label = tk.Label(self.root, bg=THEME["bg"], bd=0)
        self.bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.load_background_image()
        self.root.bind("<Configure>", self.on_root_resize)

        # Main card with a subtle border. This looks more like a kiosk panel.
        self.card_border = tk.Frame(
            self.root,
            bg=THEME["accent_dark"],
            padx=2,
            pady=2,
        )
        self.card_border.pack(fill="both", expand=True, padx=CARD_MARGIN_X, pady=CARD_MARGIN_Y)
        self.card_border.lift()

        self.card = tk.Frame(self.card_border, bg=THEME["card"], padx=18, pady=14)
        self.card.pack(fill="both", expand=True)

        self.header = tk.Frame(self.card, bg=THEME["card"])
        self.header.pack(fill="x", pady=(0, 8))

        self.brand_label = tk.Label(
            self.header,
            text="SECURE ACCESS SYSTEM",
            fg=THEME["text"],
            bg=THEME["card"],
            font=FONT_TITLE,
            anchor="w",
        )
        self.brand_label.pack(side="left")

        self.lock_pill = tk.Label(
            self.header,
            text="LOCKED",
            fg=THEME["text"],
            bg=THEME["danger_dark"],
            font=FONT_STATUS,
            padx=10,
            pady=4,
        )
        self.lock_pill.pack(side="right")

        self.step_label = tk.Label(
            self.card,
            text="01  START    02  ID SCAN    03  FACE SCAN    04  RESULT",
            fg=THEME["muted"],
            bg=THEME["card"],
            font=FONT_SMALL,
        )
        self.step_label.pack(fill="x", pady=(0, 6))

        self.display_area = tk.Frame(
            self.card,
            bg=THEME["panel"],
            width=700,
            height=265,
            highlightthickness=1,
            highlightbackground=blend_hex(THEME["panel"], THEME["accent"], 0.35),
        )
        self.display_area.pack(fill="both", expand=True, pady=(0, 8))
        self.display_area.pack_propagate(False)

        self.icon_label = tk.Label(
            self.display_area,
            text="LOCKED",
            fg=THEME["accent"],
            bg=THEME["panel"],
            font=(FONT_FAMILY, 13, "bold"),
            justify="center",
        )

        self.main_message = tk.Label(
            self.display_area,
            text="Slide to begin",
            fg=THEME["text"],
            bg=THEME["panel"],
            font=FONT_HERO,
            wraplength=620,
            justify="center",
        )
        self.sub_message = tk.Label(
            self.display_area,
            text="Camera remains hidden until your ID tag is accepted.",
            fg=THEME["muted"],
            bg=THEME["panel"],
            font=FONT_SUB,
            wraplength=620,
            justify="center",
        )

        self.video_label = tk.Label(self.display_area, bg=THEME["camera"])

        self.status_bar = tk.Frame(self.card, bg=THEME["card"])
        self.status_bar.pack(fill="x", pady=(0, 6))

        self.status_label = tk.Label(
            self.status_bar,
            text="State: Idle / Locked",
            fg=THEME["muted"],
            bg=THEME["card"],
            font=FONT_STATUS,
            anchor="w",
        )
        self.status_label.pack(side="left", fill="x", expand=True)

        self.progress_label = tk.Label(
            self.status_bar,
            text="",
            fg=THEME["accent"],
            bg=THEME["card"],
            font=FONT_STATUS,
            anchor="e",
        )
        self.progress_label.pack(side="right")

        # Public Secure Access GUI should not expose any control buttons.
        # In kiosk mode, users should only be able to use the authentication flow.
        self.button_row = None
        self.cancel_button = None
        self.quit_button = None

        if not PUBLIC_KIOSK_MODE:
            self.button_row = tk.Frame(self.card, bg=THEME["card"])
            self.button_row.pack(pady=(0, 3))

            self.cancel_button = self.make_button(
                self.button_row,
                text="Cancel / Reset",
                command=self.cancel_flow,
                width=15,
            )
            self.cancel_button.grid(row=0, column=0, padx=8)

            self.quit_button = self.make_button(
                self.button_row,
                text="Quit",
                command=self.request_quit,
                width=10,
            )
            self.quit_button.grid(row=0, column=1, padx=8)

        self.log_box = tk.Text(
            self.card,
            height=6,
            bg=THEME["log_bg"],
            fg=THEME["muted"],
            insertbackground=THEME["text"],
            font=FONT_LOG,
            state="disabled",
            wrap="word",
            relief="flat",
        )
        if SHOW_SERVICE_LOG:
            self.log_box.pack(fill="x", pady=(8, 0))

        # Start control. This replaces the old tap-anywhere behavior so accidental
        # screen touches do not begin authentication. The user must drag the slider
        # all the way to the right and release it.
        self.slider_frame = tk.Frame(self.display_area, bg=THEME["panel"])
        self.slider_hint = tk.Label(
            self.slider_frame,
            text="Slide all the way right to begin",
            fg=THEME["muted"],
            bg=THEME["panel"],
            font=FONT_STATUS,
        )
        self.slider_hint.pack(pady=(0, 4))

        self.slider = tk.Scale(
            self.slider_frame,
            from_=0,
            to=100,
            orient="horizontal",
            variable=self.slider_var,
            showvalue=False,
            length=500,
            sliderlength=70,
            width=24,
            bd=0,
            relief="flat",
            troughcolor=THEME["panel_alt"],
            bg=THEME["panel"],
            activebackground=THEME["accent"],
            highlightthickness=0,
            command=self.on_slider_move,
        )
        self.slider.pack()
        self.slider.bind("<ButtonRelease-1>", self.on_slider_release)

        self.show_idle_screen()
        self.create_admin_window()

    def load_background_image(self):
        if not USE_BACKGROUND_IMAGE:
            log_event("Background image disabled in settings.")
            return

        checked_paths = []

        try:
            for path in BACKGROUND_IMAGE_CANDIDATES:
                path = os.path.expanduser(path)
                checked_paths.append(path)

                if os.path.isfile(path):
                    self.bg_original = Image.open(path).convert("RGB")
                    log_event(f"Background image loaded: {path}")
                    self.root.after(100, self.refresh_background)
                    return

            # Fallback: use the first PNG/JPG file in Downloads whose name contains
            # 'background'. This helps if your image name is slightly different.
            downloads = "/home/aas/Downloads"
            if os.path.isdir(downloads):
                image_files = sorted(
                    f for f in os.listdir(downloads)
                    if "background" in f.lower()
                    and f.lower().endswith((".png", ".jpg", ".jpeg", ".webp"))
                )

                if image_files:
                    path = os.path.join(downloads, image_files[0])
                    self.bg_original = Image.open(path).convert("RGB")
                    log_event(f"Background image auto-detected: {path}")
                    self.root.after(100, self.refresh_background)
                    return

            log_event("No background image found. Checked: " + ", ".join(checked_paths))

        except Exception as e:
            self.bg_original = None
            log_event(f"Could not load background image: {e}")

    def on_root_resize(self, event=None):
        # Only the root resize should refresh the background. Child widgets also
        # generate Configure events, so ignore those.
        if event is not None and event.widget is not self.root:
            return
        self.refresh_background()

    def refresh_background(self):
        if self.bg_original is None:
            return

        width = max(1, self.root.winfo_width())
        height = max(1, self.root.winfo_height())
        size = (width, height)

        if size == self.last_bg_size:
            return

        bg = cover_resize(self.bg_original, width, height)
        bg = dim_image(bg, BACKGROUND_DIM_OVERLAY)
        self.bg_photo = ImageTk.PhotoImage(bg)
        self.bg_label.configure(image=self.bg_photo)
        self.bg_label.lower()
        self.last_bg_size = size

    def make_button(self, parent, text, command, width=12):
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            font=FONT_BUTTON,
            width=width,
            fg=THEME["button_text"],
            bg=THEME["button"],
            activeforeground=THEME["button_text"],
            activebackground=THEME["button_hover"],
            relief="flat",
            bd=0,
            padx=8,
            pady=5,
            cursor="hand2",
        )
        return btn

    def show_idle_screen(self):
        self.slider_var.set(0)
        self.show_message_screen(
            title="Slide to begin",
            subtitle="Camera remains hidden until your ID tag is accepted.",
            bg=THEME["panel"],
            state_text="State: Idle / Locked",
            icon="LOCKED",
            step=1,
            pill_text="LOCKED",
            pill_bg=THEME["danger_dark"],
            show_slider=True,
        )

    def on_slider_move(self, value):
        # Avoid starting immediately while the user is still dragging. The flow
        # starts only on release when the slider is near the end.
        try:
            value = int(float(value))
        except ValueError:
            value = 0

        if self.slider_hint is not None:
            if value >= 95:
                self.slider_hint.configure(text="Release to begin")
            else:
                self.slider_hint.configure(text="Slide all the way right to begin")

    def on_slider_release(self, event=None):
        if self.slider_var.get() >= 95:
            self.begin_authentication()
        else:
            self.slider_var.set(0)
            if self.slider_hint is not None:
                self.slider_hint.configure(text="Slide all the way right to begin")

    def create_admin_window(self):
        self.admin = tk.Toplevel(self.root)
        self.admin.title("MFA Admin Control Panel")
        # Open admin/control panel on the HDMI monitor when detected.
        self.admin.geometry(self.admin_geometry)
        self.admin.configure(bg="#101820")

        title = tk.Label(
            self.admin,
            text="Admin Control Panel",
            fg="white",
            bg="#101820",
            font=(FONT_FAMILY, 20, "bold"),
        )
        title.pack(pady=(10, 5))

        top = tk.Frame(self.admin, bg="#101820")
        top.pack(fill="both", expand=True, padx=10, pady=10)

        left = tk.Frame(top, bg="#101820")
        left.pack(side="left", fill="y", padx=(0, 10))

        right = tk.Frame(top, bg="#101820")
        right.pack(side="right", fill="both", expand=True)

        tk.Label(left, text="Users", fg="white", bg="#101820", font=FONT_STATUS).pack(anchor="w")
        self.user_listbox = tk.Listbox(left, width=42, height=18, font=(FONT_FAMILY, 10))
        self.user_listbox.pack(pady=(3, 8))

        btn_row = tk.Frame(left, bg="#101820")
        btn_row.pack(fill="x", pady=(0, 8))
        tk.Button(btn_row, text="Refresh", command=self.refresh_admin_users, width=10).grid(row=0, column=0, padx=3)
        tk.Button(btn_row, text="Disable", command=self.disable_selected_user, width=10).grid(row=0, column=1, padx=3)
        tk.Button(btn_row, text="Enable", command=self.enable_selected_user, width=10).grid(row=0, column=2, padx=3)
        tk.Button(btn_row, text="Remove", command=self.remove_selected_user, width=10).grid(row=0, column=3, padx=3)

        tk.Label(left, text="Add / Enroll User", fg="white", bg="#101820", font=FONT_STATUS).pack(anchor="w", pady=(12, 2))
        form = tk.Frame(left, bg="#101820")
        form.pack(fill="x")

        tk.Label(form, text="Name:", fg="white", bg="#101820").grid(row=0, column=0, sticky="w", pady=2)
        self.admin_name_entry = tk.Entry(form, width=28)
        self.admin_name_entry.grid(row=0, column=1, sticky="w", pady=2)

        tk.Label(form, text="RFID:", fg="white", bg="#101820").grid(row=1, column=0, sticky="w", pady=2)
        self.admin_tag_var = tk.StringVar(value="")
        self.admin_tag_entry = tk.Entry(form, width=28, textvariable=self.admin_tag_var)
        self.admin_tag_entry.grid(row=1, column=1, sticky="w", pady=2)

        tk.Button(left, text="Scan RFID for New User", command=self.admin_scan_rfid, width=28).pack(pady=(8, 4))
        tk.Button(left, text="Capture Face Images + Save User", command=self.admin_start_enrollment, width=28).pack(pady=4)
        tk.Button(left, text="Cancel Enrollment", command=self.admin_cancel_enrollment, width=28).pack(pady=4)

        self.admin_status = tk.Label(
            left,
            text="Ready",
            fg=THEME["accent"],
            bg="#101820",
            wraplength=360,
            justify="left",
            font=FONT_SMALL,
        )
        self.admin_status.pack(fill="x", pady=(8, 5))

        # Right side layout is intentionally fixed so the log and admin buttons
        # are always visible. In the previous version, the enrollment preview used
        # expand=True and could push the Admin/Security Log and buttons off-screen.
        tk.Label(right, text="Enrollment Preview", fg="white", bg="#101820", font=FONT_STATUS).pack(anchor="w")

        preview_frame = tk.Frame(right, bg="black", height=300)
        preview_frame.pack(fill="x", expand=False, pady=(3, 8))
        preview_frame.pack_propagate(False)

        self.admin_preview_label = tk.Label(preview_frame, bg="black", width=640, height=300)
        self.admin_preview_label.pack(fill="both", expand=True)
        self.admin_preview_ref = None

        log_header_row = tk.Frame(right, bg="#101820")
        log_header_row.pack(fill="x", pady=(0, 2))
        tk.Label(log_header_row, text="Admin / Security Log", fg="white", bg="#101820", font=FONT_STATUS).pack(side="left")

        log_frame = tk.Frame(right, bg="#07111f", height=170)
        log_frame.pack(fill="both", expand=True)
        log_frame.pack_propagate(False)

        self.admin_log_box = tk.Text(log_frame, height=8, bg="#07111f", fg="#d9e6f2", font=FONT_LOG, wrap="word")
        self.admin_log_box.pack(side="left", fill="both", expand=True)

        log_scroll = tk.Scrollbar(log_frame, command=self.admin_log_box.yview)
        log_scroll.pack(side="right", fill="y")
        self.admin_log_box.configure(yscrollcommand=log_scroll.set)

        log_buttons = tk.Frame(right, bg="#101820")
        log_buttons.pack(fill="x", pady=(6, 0))
        tk.Button(log_buttons, text="Load Recent Logs", command=self.load_recent_logs, width=16).pack(side="left", padx=3)
        tk.Button(log_buttons, text="Reload Faces", command=self.admin_reload_faces, width=14).pack(side="left", padx=3)
        tk.Button(log_buttons, text="Shutdown Program", command=self.request_quit, width=18).pack(side="right", padx=3)

        self.refresh_admin_users()
        self.load_recent_logs()
        admin_event("Admin control panel ready.")

    def selected_user_tag(self):
        if not hasattr(self, "user_listbox"):
            return None
        selection = self.user_listbox.curselection()
        if not selection:
            return None
        line = self.user_listbox.get(selection[0])
        # Format is: [ACTIVE] Name | tag=1234
        if "tag=" not in line:
            return None
        return line.split("tag=", 1)[1].strip()

    def refresh_admin_users(self):
        if not hasattr(self, "user_listbox"):
            return
        self.user_listbox.delete(0, "end")
        users = load_users()
        for tag_id, info in sorted(users.items(), key=lambda item: item[1].get("name", "")):
            status = "ACTIVE" if info.get("active", True) else "DISABLED"
            self.user_listbox.insert("end", f"[{status}] {info.get('name', 'Unknown')} | tag={tag_id}")

    def admin_scan_rfid(self):
        ok = start_admin_rfid_scan()
        if ok:
            self.admin_status.configure(text="Scan the new user's RFID card now...")

    def admin_start_enrollment(self):
        name = self.admin_name_entry.get().strip()
        tag_id = self.admin_tag_var.get().strip()
        if not tag_id and admin_pending_tag_id is not None:
            tag_id = str(admin_pending_tag_id)
            self.admin_tag_var.set(tag_id)
        if start_face_enrollment(name, tag_id, target_count=18):
            self.admin_status.configure(text=f"Capturing face images for {name}. Look at the camera.")

    def admin_cancel_enrollment(self):
        stop_face_enrollment(cancelled=True)
        self.admin_status.configure(text="Enrollment cancelled.")

    def disable_selected_user(self):
        tag = self.selected_user_tag()
        if tag and set_user_active(tag, False):
            record_audit_event(event_type="admin_disable_user", tag_id=tag, outcome="disabled")
            self.refresh_admin_users()
            self.admin_status.configure(text="User disabled.")

    def enable_selected_user(self):
        tag = self.selected_user_tag()
        if tag and set_user_active(tag, True):
            record_audit_event(event_type="admin_enable_user", tag_id=tag, outcome="enabled")
            self.refresh_admin_users()
            self.admin_status.configure(text="User enabled.")

    def remove_selected_user(self):
        tag = self.selected_user_tag()
        if tag and remove_user(tag, archive_faces=True):
            record_audit_event(event_type="admin_remove_user", tag_id=tag, outcome="removed")
            self.refresh_admin_users()
            self.admin_status.configure(text="User removed. Reloading face database in background...")
            reload_known_faces_async(reason="user removed")

    def admin_reload_faces(self):
        self.admin_status.configure(text="Reloading face database in background...")
        reload_known_faces_async(reason="admin requested reload")

    def append_admin_log(self, line):
        if not hasattr(self, "admin_log_box"):
            return
        self.admin_log_box.insert("end", line + "\n")
        self.admin_log_box.see("end")

    def process_admin_queue(self):
        while True:
            try:
                line = admin_queue.get_nowait()
            except queue.Empty:
                break
            self.append_admin_log(line)
            if hasattr(self, "admin_status"):
                self.admin_status.configure(text=line)
            if admin_pending_tag_id is not None and hasattr(self, "admin_tag_var"):
                self.admin_tag_var.set(str(admin_pending_tag_id))

    def load_recent_logs(self):
        if not hasattr(self, "admin_log_box"):
            return
        self.admin_log_box.delete("1.0", "end")
        if not os.path.isfile(AUDIT_LOG_FILE):
            self.admin_log_box.insert("end", "No audit log yet.\n")
            return
        try:
            with open(AUDIT_LOG_FILE, "r") as f:
                lines = f.readlines()[-40:]
            self.admin_log_box.insert("end", "".join(lines))
            self.admin_log_box.see("end")
        except Exception as e:
            self.admin_log_box.insert("end", f"Could not load logs: {e}\n")

    def update_admin_preview(self, frame, message=""):
        if not hasattr(self, "admin_preview_label"):
            return
        image = Image.fromarray(frame)
        max_w = max(1, self.admin_preview_label.winfo_width())
        max_h = max(1, self.admin_preview_label.winfo_height())
        image.thumbnail((max_w, max_h), Image.LANCZOS)
        photo = ImageTk.PhotoImage(image=image)
        self.admin_preview_label.configure(image=photo)
        self.admin_preview_ref = photo
        if message and hasattr(self, "admin_status"):
            self.admin_status.configure(text=message)

    def toggle_fullscreen(self):
        if PUBLIC_KIOSK_MODE:
            # Public GUI is intentionally locked in kiosk mode.
            return
        self.fullscreen = not self.fullscreen
        self.root.attributes("-fullscreen", self.fullscreen)

    def begin_authentication(self):
        global rfid_verified_user, rfid_verified_tag_id, rfid_verified_time
        state, _, _ = get_system_state()
        if state == STATE_IDLE:
            rfid_verified_user = None
            rfid_verified_tag_id = None
            rfid_verified_time = 0.0
            deny_and_reset()
            set_system_state(STATE_WAIT_RFID, "Scan your ID tag", time.time() + WAIT_RFID_TIMEOUT)
            log_event("Slider completed. Waiting for RFID tag.")

    def cancel_flow(self):
        global rfid_verified_user, rfid_verified_tag_id, rfid_verified_time, auth_busy_until
        rfid_verified_user = None
        rfid_verified_tag_id = None
        rfid_verified_time = 0.0
        auth_busy_until = 0.0
        deny_and_reset()
        set_system_state(STATE_IDLE, "Slide to begin", 0.0)
        log_event("Flow cancelled/reset.")

    def request_quit(self):
        self.running = False

    def add_log_line(self, line):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def process_log_queue(self):
        while True:
            try:
                line = event_log.get_nowait()
            except queue.Empty:
                break
            self.add_log_line(line)

    def clear_display(self):
        self.video_label.pack_forget()
        self.icon_label.pack_forget()
        self.main_message.pack_forget()
        self.sub_message.pack_forget()
        if self.slider_frame is not None:
            self.slider_frame.pack_forget()

    def set_steps(self, active_step):
        labels = ["START", "ID", "FACE", "RESULT"]
        parts = []
        for i, label in enumerate(labels, start=1):
            marker = "●" if i == active_step else "○"
            parts.append(f"{marker}  {i:02d} {label}")
        self.step_label.configure(text="   ".join(parts))

    def show_message_screen(
        self,
        title,
        subtitle="",
        bg=None,
        state_text="",
        icon="",
        step=1,
        pill_text="LOCKED",
        pill_bg=None,
        show_slider=False,
    ):
        bg = bg or THEME["panel"]
        pill_bg = pill_bg or THEME["danger_dark"]

        if self.current_screen != ("message", title, subtitle, bg, icon, show_slider):
            self.clear_display()
            self.display_area.configure(bg=bg, highlightbackground=blend_hex(bg, THEME["accent"], 0.35))
            self.icon_label.configure(text=icon, bg=bg)
            self.main_message.configure(text=title, bg=bg)
            self.sub_message.configure(text=subtitle, bg=bg)

            if self.slider_frame is not None:
                self.slider_frame.configure(bg=bg)
            if self.slider_hint is not None:
                self.slider_hint.configure(bg=bg)
            if self.slider is not None:
                self.slider.configure(bg=bg)

            # Compact layout for the 7-inch Raspberry Pi display. Do not use
            # expand=True for these labels, otherwise the slider can get pushed
            # off the bottom of the screen.
            self.icon_label.pack(pady=(18, 4))
            self.main_message.pack(fill="x", pady=(2, 8))
            if show_slider and self.slider_frame is not None:
                self.slider_frame.pack(pady=(0, 8))
            self.sub_message.pack(fill="x", pady=(0, 10))
            self.current_screen = ("message", title, subtitle, bg, icon, show_slider)

        self.status_label.configure(text=state_text)
        self.lock_pill.configure(text=pill_text, bg=pill_bg)
        self.set_steps(step)

    def show_camera_screen(self, frame, state_text, progress_text):
        # Only switch/pack widgets when entering the camera screen.
        # Repacking the camera label every frame causes visible flicker.
        if self.current_screen != ("camera",):
            self.clear_display()
            self.display_area.configure(
                bg=THEME["camera"],
                highlightbackground=blend_hex(THEME["camera"], THEME["accent"], 0.45),
            )
            self.video_label.configure(bg=THEME["camera"])
            self.video_label.pack(expand=True, fill="both")
            self.current_screen = ("camera",)

        image = Image.fromarray(frame)
        # Fit the live feed inside the current display area so it does not
        # overflow smaller Raspberry Pi touchscreens.
        max_w = max(1, self.display_area.winfo_width() - 8)
        max_h = max(1, self.display_area.winfo_height() - 8)
        image.thumbnail((max_w, max_h), Image.LANCZOS)
        photo = ImageTk.PhotoImage(image=image)
        self.video_label.configure(image=photo)
        self.image_ref = photo

        self.status_label.configure(text=state_text)
        self.progress_label.configure(text=progress_text)
        self.lock_pill.configure(text="VERIFYING", bg=THEME["accent_dark"])
        self.set_steps(3)

    def update_for_state(self, frame, rfid_status, auth_name, consec_count, fps):
        state, message, until = get_system_state()
        now = time.time()
        remaining = max(0, int(until - now)) if until else 0
        self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
        spinner = self.spinner_chars[self.spinner_index]

        if state == STATE_IDLE:
            self.progress_label.configure(text="")
            if self.current_screen != ("message", "Slide to begin", "Camera remains hidden until your ID tag is accepted.", THEME["panel"], "LOCKED", True):
                self.show_idle_screen()
            else:
                self.status_label.configure(text="State: Idle / Locked")
                self.lock_pill.configure(text="LOCKED", bg=THEME["danger_dark"])
                self.set_steps(1)

        elif state == STATE_WAIT_RFID:
            self.progress_label.configure(text=f"{remaining}s")
            self.show_message_screen(
                title="Scan your ID tag",
                subtitle="Hold your RFID card near the reader.",
                bg=THEME["panel_alt"],
                state_text="State: Waiting for ID / Locked",
                icon="ID REQUIRED",
                step=2,
                pill_text="LOCKED",
                pill_bg=THEME["danger_dark"],
            )

        elif state == STATE_FACE_AUTH:
            # Keep public display clean: no face name, no FPS, no debug confidence.
            progress = f"Verifying identity  {spinner}   {remaining}s"
            self.show_camera_screen(
                frame=frame,
                state_text="State: Face verification in progress",
                progress_text=progress,
            )

        elif state == STATE_SUCCESS:
            self.progress_label.configure(text=f"Locking in {remaining}s")
            self.show_message_screen(
                title="VERIFIED",
                subtitle=message or "Access granted. Door unlocked.",
                bg=blend_hex(THEME["success_dark"], THEME["success"], 0.45),
                state_text="State: Verified / Unlocked",
                icon="ACCESS GRANTED",
                step=4,
                pill_text="UNLOCKED",
                pill_bg=THEME["success"],
            )

        elif state == STATE_DENIED:
            self.progress_label.configure(text=f"Resetting in {remaining}s")
            self.show_message_screen(
                title="ACCESS DENIED",
                subtitle=message or "Authentication failed.",
                bg=blend_hex(THEME["danger_dark"], THEME["danger"], 0.45),
                state_text="State: Invalid / Locked",
                icon="TRY AGAIN",
                step=4,
                pill_text="LOCKED",
                pill_bg=THEME["danger"],
            )

    def update_gui(self):
        self.process_log_queue()
        self.process_admin_queue()
        self.root.update_idletasks()
        self.root.update()

    def destroy(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass


def trigger_unlock(name):
    global rfid_verified_user, rfid_verified_tag_id, auth_busy_until

    now = time.time()
    scanned_user = rfid_verified_user
    scanned_tag_id = rfid_verified_tag_id

    if scanned_user is None:
        log_event("DENIED: No RFID scan detected")
        record_audit_event(event_type="access_denied", user=name, tag_id=scanned_tag_id, outcome="denied", reason="no valid RFID scan detected")
        set_system_state(STATE_DENIED, "No valid ID scan detected", now + RESULT_SCREEN_TIME)
        return False

    if now - rfid_verified_time > RFID_TIMEOUT:
        log_event("DENIED: RFID scan expired")
        record_audit_event(event_type="access_denied", user=scanned_user, tag_id=scanned_tag_id, outcome="denied", reason="RFID scan expired before face verification")
        rfid_verified_user = None
        rfid_verified_tag_id = None
        deny_and_reset()
        set_system_state(STATE_DENIED, "ID scan expired. Try again.", now + RESULT_SCREEN_TIME)
        return False

    if scanned_user.lower() != name.lower():
        log_event(f"DENIED: Face is {name} but RFID was {scanned_user}")
        record_audit_event(event_type="access_denied", user=scanned_user, tag_id=scanned_tag_id, outcome="denied", reason=f"face/RFID mismatch: face={name}, rfid={scanned_user}")
        rfid_verified_user = None
        rfid_verified_tag_id = None
        deny_and_reset()
        set_system_state(STATE_DENIED, "Face does not match the scanned ID", now + RESULT_SCREEN_TIME)
        return False

    anomaly = evaluate_login_anomaly(name)
    record_audit_event(
        event_type="access_granted",
        user=name,
        tag_id=scanned_tag_id,
        outcome="granted",
        reason="RFID and face matched",
        anomaly_flag=anomaly["flag"],
        anomaly_score=anomaly["score"],
        details=anomaly["reason"],
    )
    build_user_profiles()

    log_event(f"ACCESS GRANTED: {name}")
    if anomaly["flag"]:
        log_event(f"ANOMALY ALERT for {name}: {anomaly['reason']}")
        admin_event(f"ANOMALY ALERT for {name}: {anomaly['reason']}")

    # Clear the RFID immediately so it cannot be reused.
    rfid_verified_user = None
    rfid_verified_tag_id = None

    # Block new RFID scans while the system is unlocking/cooling down.
    auth_busy_until = now + AUTH_BUSY_TIME

    msg = f"Welcome, {name}. Door unlocked."
    if anomaly["flag"] and SHOW_ANOMALY_ON_GUI:
        msg = f"Welcome, {name}. Door unlocked. Admin alert logged."
    set_system_state(STATE_SUCCESS, msg, now + AUTH_BUSY_TIME)

    t = threading.Thread(target=unlock_hardware, args=(name,))
    t.daemon = True
    t.start()

    return True


ensure_user_db()
load_known_faces()
record_audit_event(event_type="system_start", outcome="ok", reason="program started")

rfid_thread = threading.Thread(target=rfid_loop)
rfid_thread.daemon = True
rfid_thread.start()

picam2.start()
time.sleep(2)

last_good = None
last_good_time = 0.0
last_print = 0.0
prev_time = time.perf_counter()
fps = 0.0

candidate_name = None
consec_count = 0
miss_count = 0

unlock_cooldown_until = 0.0
unlock_text_until = 0.0
last_unlock_name = None
last_auth_log_time = 0.0
last_auth_log_text = ""

gui = MFAInteractiveGUI()

log_event("System ready. Slide to begin.")

try:
    while True:
        req = picam2.capture_request()
        frame = req.make_array("main")
        metadata = req.get_metadata()
        now = time.time()

        # Admin enrollment uses the same camera stream. Capture face images only
        # while enrollment is active, then keep the public GUI idle.
        if enrollment_active:
            frame = process_enrollment_frame(frame, metadata, now)
            if gui is not None:
                gui.update_admin_preview(
                    frame,
                    f"Enrolling {enrollment_name}: {enrollment_count}/{enrollment_target_count} images"
                )

        # Check if RFID/face-authentication window has expired.
        if rfid_verified_user is not None and (now - rfid_verified_time) > RFID_TIMEOUT:
            log_event("Face authentication timed out.")
            record_audit_event(event_type="access_denied", user=rfid_verified_user, tag_id=rfid_verified_tag_id, outcome="denied", reason="face authentication timed out")
            rfid_verified_user = None
            rfid_verified_tag_id = None
            deny_and_reset()
            set_system_state(STATE_DENIED, "Face authentication timed out", now + RESULT_SCREEN_TIME)

            # Clear face recognition state when RFID expires.
            candidate_name = None
            consec_count = 0
            miss_count = 0
            last_good = None

        state, message, state_until_value = get_system_state()

        # Handle timed GUI states.
        if state == STATE_WAIT_RFID and state_until_value and now > state_until_value:
            record_audit_event(event_type="rfid_timeout", outcome="timeout", reason="user started flow but did not scan RFID")
            set_system_state(STATE_IDLE, "Slide to begin", 0.0)
            log_event("RFID scan timed out. Returning to idle.")

        elif state in (STATE_SUCCESS, STATE_DENIED) and state_until_value and now > state_until_value:
            set_system_state(STATE_IDLE, "Slide to begin", 0.0)
            log_event("Returning to idle.")

        state, message, state_until_value = get_system_state()

        # This variable controls whether face detection/recognition is allowed.
        # The camera feed and face recognition only happen after a valid RFID scan.
        rfid_active = (
            not enrollment_active
            and state == STATE_FACE_AUTH
            and rfid_verified_user is not None
            and (now - rfid_verified_time) <= RFID_TIMEOUT
            and now >= auth_busy_until
        )

        chosen = None

        # IMPORTANT:
        # Face detection and recognition only run after a valid RFID scan.
        if rfid_active:
            dets, info = decode_outputs(metadata)

            if dets:
                strong = []

                for d in dets:
                    if d["score"] >= SCORE_THRESH and d["class"] == 0:
                        px1, py1, px2, py2 = model_to_preview_box(
                            *d["box"],
                            PREVIEW_W,
                            PREVIEW_H
                        )

                        if px2 > px1 and py2 > py1:
                            d["preview_box"] = [px1, py1, px2, py2]
                            strong.append(d)

                if strong:
                    strong.sort(key=lambda x: x["score"], reverse=True)
                    chosen = strong[0]

                    x1, y1, x2, y2 = chosen["preview_box"]

                    face_crop, known_face_location = make_padded_crop(
                        frame,
                        x1,
                        y1,
                        x2,
                        y2
                    )

                    name, dist = recognize_face(face_crop, known_face_location)

                    chosen["name"] = name
                    chosen["dist"] = dist

                    last_good = chosen
                    last_good_time = now

        else:
            # No valid RFID scan, so do not show old recognition data
            candidate_name = None
            consec_count = 0
            miss_count = 0
            last_good = None

        recognized_name = None

        if chosen and chosen["name"] != "Unknown":
            recognized_name = chosen["name"]

        if recognized_name is not None:
            if candidate_name == recognized_name:
                consec_count += 1
            else:
                candidate_name = recognized_name
                consec_count = 1

            miss_count = 0

            # Terminal-only debug so you can confirm recognition is still counting
            # without showing labels on the camera feed.
            dist_text = ""
            if chosen is not None and chosen.get("dist") is not None:
                dist_text = f" avg_dist={chosen['dist']:.3f}"

            auth_log_text = f"Face recognized: {candidate_name} {consec_count}/{REQUIRED_CONSEC_FRAMES}{dist_text}"
            if auth_log_text != last_auth_log_text or (now - last_auth_log_time) > 1.0:
                log_event(auth_log_text)
                last_auth_log_text = auth_log_text
                last_auth_log_time = now

        else:
            if candidate_name is not None:
                miss_count += 1

                if miss_count > MAX_MISSES:
                    candidate_name = None
                    consec_count = 0
                    miss_count = 0

        if (
            candidate_name is not None
            and consec_count >= REQUIRED_CONSEC_FRAMES
            and now >= unlock_cooldown_until
        ):
            unlocked = trigger_unlock(candidate_name)

            if unlocked:
                last_unlock_name = candidate_name
                unlock_cooldown_until = now + AUTH_BUSY_TIME
                unlock_text_until = now + 1.5

            candidate_name = None
            consec_count = 0
            miss_count = 0

        # Only draw face box/name when RFID is active
        if rfid_active and chosen:
            txt = chosen["name"]
            txt += " (RFID OK)"
            draw_detection(frame, chosen, txt, (0, 255, 0))

        elif rfid_active and last_good and (now - last_good_time) < HOLD_SECONDS:
            draw_detection(frame, last_good, last_good["name"], (0, 200, 255))

        current_time = time.perf_counter()
        dt = current_time - prev_time

        if dt > 0:
            instant_fps = 1.0 / dt
            fps = instant_fps if fps == 0.0 else 0.90 * fps + 0.10 * instant_fps

        prev_time = current_time

        if now < auth_busy_until:
            time_left = int(auth_busy_until - now)
            rfid_status = f"System busy/unlocked - wait ({time_left}s)"

        elif rfid_active:
            time_left = int(RFID_TIMEOUT - (now - rfid_verified_time))
            rfid_status = f"Face the camera ({time_left}s)"

        else:
            state, _, _ = get_system_state()
            if state == STATE_WAIT_RFID:
                rfid_status = "Waiting for ID tag"
            elif state == STATE_IDLE:
                rfid_status = "Slide to begin"
            else:
                rfid_status = state

        auth_name = candidate_name if candidate_name is not None else "-"

        # Release the camera request before updating the Tkinter GUI.
        req.release()

        if gui is not None:
            gui.update_for_state(
                frame=frame,
                rfid_status=rfid_status,
                auth_name=auth_name,
                consec_count=consec_count,
                fps=fps,
            )
            gui.update_gui()

            if not gui.running:
                break


finally:
    try:
        cv2.destroyAllWindows()
    except Exception:
        pass
    picam2.stop()
    relay_off()
    led_off()
    lgpio.gpiochip_close(h)
    if gui is not None:
        gui.destroy()
