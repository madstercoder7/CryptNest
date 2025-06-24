import face_recognition
import cv2
import numpy as np
import os
import shutil

ENCODING_DIR = "face_data"
TEMP_FACE_PATH = os.path.join(ENCODING_DIR, "temp_face.npy")
os.makedirs(ENCODING_DIR, exist_ok=True)

def capture_face_temp():
    video = cv2.VideoCapture(0)
    face_encoding = None

    while True:
        ret, frame = video.read()
        if not ret:
            continue

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)

        if face_locations:
            largest_face = sorted(
                face_locations,
                key=lambda loc: (loc[2] - loc[0]) * (loc[1] - loc[3]),
                reverse=True
            )[0]
            face_encoding = face_recognition.face_encodings(rgb_frame, [largest_face])[0]

            top, right, bottom, left = largest_face
            cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
            cv2.putText(
                frame,
                "Face detected - Press 's' to save",
                (10, 30),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (0, 255, 0),
                2
            )

        cv2.imshow("Capture Face", frame)
        key = cv2.waitKey(1)
        if key == ord('s') and face_encoding is not None:
            np.save(TEMP_FACE_PATH, face_encoding)
            break
        elif key == ord('q'):
            break

    video.release()
    cv2.destroyAllWindows()
    return face_encoding is not None


def move_temp_face_to_user(user_id):
    user_path = os.path.join(ENCODING_DIR, f"{user_id}_face.npy")
    if os.path.exists(TEMP_FACE_PATH):
        shutil.move(TEMP_FACE_PATH, user_path)


def verify_face_against_encodings():
    video = cv2.VideoCapture(0)
    known_encodings = []
    user_ids = []

    for file in os.listdir(ENCODING_DIR):
        if file.endswith('.npy') and not file.startswith("temp_"):
            user_id = file.split("_")[0]
            encoding = np.load(os.path.join(ENCODING_DIR, file))
            known_encodings.append(encoding)
            user_ids.append(user_id)

    matched_user_id = None
    timeout_frames = 100

    while timeout_frames > 0:
        ret, frame = video.read()
        if not ret:
            continue

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)

        if face_locations:
            largest_face = sorted(
                face_locations,
                key=lambda loc: (loc[2] - loc[0]) * (loc[1] - loc[3]),
                reverse=True
            )[0]
            face_encoding = face_recognition.face_encodings(rgb_frame, [largest_face])[0]
            results = face_recognition.compare_faces(known_encodings, face_encoding)

            if True in results:
                matched_index = results.index(True)
                matched_user_id = int(user_ids[matched_index])
                break

        timeout_frames -= 1
        cv2.imshow("Verifying Face", frame)
        if cv2.waitKey(1) == ord('q'):
            break

    video.release()
    cv2.destroyAllWindows()
    return matched_user_id
