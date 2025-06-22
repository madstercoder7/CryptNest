import face_recognition
import cv2
import numpy as np
import os

ENCODING_DIR = "face_data"
os.makedirs(ENCODING_DIR, exist_ok=True)

def capture_and_save_face(user_id):
    video = cv2.VideoCapture(0)
    print("Capturing face... Press 's' to save once your face is detected.")

    face_encoding = None

    while True:
        ret, frame = video.read()
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        face_locations = face_recognition.face_locations(rgb_frame)
        if face_locations:
            face_encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]
            cv2.rectangle(frame, (face_locations[0][3], face_locations[0][0]), (face_locations[0][1], face_locations[0][2]), (0, 255, 0), 2)
            cv2.putText(frame, "Face Detected - Press 's' to save", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

        cv2.imshow("Capture face", frame)

        key = cv2.waitKey(1)
        if key == ord('s') and face_encoding is not None:
            file_path = os.path.join(ENCODING_DIR, f"{user_id}_face.npy")
            np.save(file_path, face_encoding)
            print("Face encoding saved successfully")
            break
        elif key == ord('q'):
            print("Cancelled")
            break

    video.release()
    cv2.destroyAllWindows()

def verify_face(user_id):
    file_path = os.path.join(ENCODING_DIR, f"{user_id}_face.npy")
    if not os.path.exists(file_path):
        print("No face encoding found. Please enroll first")
        return False
    
    known_encoding = np.load(file_path)

    video = cv2.VideoCapture(0)
    print("Looking for a face to verify...")

    matched = False
    timeout_frames = 100

    while timeout_frames > 0:
        ret, frame = video.read()
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        face_locations = face_recognition.face_locations(rgb_frame)
        if face_locations:
            face_encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]
            results = face_recognition.compare_faces([known_encoding], face_encoding)

            if results[0]:
                print("Face match successful")
                matched = True
                break
            else:
                print("Face not recognized. Try again...")

        timeout_frames -= 1
        cv2.imshow("Verifying face", frame)
        if cv2.waitKey(1) == ord('q'):
            break

    video.release()
    cv2.destroyAllWindows()
    return matched