import face_recognition
import face_recognition_models
import cv2
import numpy as np
import os

ENCODING_DIR = "face_data"
os.makedirs(ENCODING_DIR, exist_ok=True)

def capture_and_save_face(user_id):
    video = cv2.VideoCapture(0)
    print("Capturing face... Press 's' to save. Press 'q' to quit.")
    face_encoding = None

    while True:
        ret, frame = video.read()
        if not ret:
            continue

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)

        if face_locations:
            largest_face = sorted(face_locations, key=lambda loc: (loc[2]-loc[0])*(loc[1]-loc[3]), reverse=True)[0]
            face_encoding = face_recognition.face_encodings(rgb_frame, [largest_face])[0]

            top, right, bottom, left = largest_face
            cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
            cv2.putText(frame, "Face Detected - Press 's' to save", (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

        cv2.imshow("Capture Face", frame)

        key = cv2.waitKey(1)
        if key == ord('s') and face_encoding is not None:
            np.save(os.path.join(ENCODING_DIR, f"{user_id}_face.npy"), face_encoding)
            print("Face encoding saved.")
            break
        elif key == ord('q'):
            print("Capture cancelled.")
            break

    video.release()
    cv2.destroyAllWindows()

def verify_face_against_encodings():
    video = cv2.VideoCapture(0)
    print("Looking for a matching face...")

    user_files = [f for f in os.listdir(ENCODING_DIR) if f.endswith('.npy')]
    known_encodings = []
    user_ids = []

    for file in user_files:
        user_id = file.split('_')[0]
        path = os.path.join(ENCODING_DIR, file)
        encoding = np.load(path)
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
            largest_face = sorted(face_locations, key=lambda loc: (loc[2]-loc[0])*(loc[1]-loc[3]), reverse=True)[0]
            face_encoding = face_recognition.face_encodings(rgb_frame, [largest_face])[0]
            results = face_recognition.compare_faces(known_encodings, face_encoding)

            if True in results:
                matched_index = results.index(True)
                matched_user_id = int(user_ids[matched_index])
                print(f"Matched with user ID: {matched_user_id}")
                break
            else:
                print("No match. Try again.")

        timeout_frames -= 1
        cv2.imshow("Verifying Face", frame)
        if cv2.waitKey(1) == ord('q'):
            break

    video.release()
    cv2.destroyAllWindows()
    return matched_user_id
