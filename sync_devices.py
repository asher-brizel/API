import requests
import os

# הגדרות סביבה (נלקח מ-GitHub Secrets)
BASE44_API_URL = "https://kehilnet.base44.app/api"
MASTER_KEY = os.getenv("BASE44_MASTER_KEY")

headers = {
    "api_key": MASTER_KEY,
    "Content-Type": "application/json"
}

def xor_encrypt(data, key):
    """הצפנת XOR פשוטה להעברת המפתח בבטחה"""
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def sync_and_authorize():
    print("--- Starting Device Sync & Authorization ---")
    
    # 1. משיכת כל המכשירים הרשומים
    response = requests.get(f"{BASE44_API_URL}/entities/UserDevice", headers=headers)
    if response.status_code != 200:
        print(f"Error fetching devices: {response.text}")
        return

    devices = response.json()
    
    # מיפוי מכשירים לפי device_id כדי לזהות כפילויות
    device_map = {}
    for device in devices:
        d_id = device.get('device_id')
        if d_id not in device_map:
            device_map[d_id] = []
        device_map[d_id].append(device)

    for d_id, records in device_map.items():
        # 2. טיפול בכפילויות: מחפשים את הרשומה המלאה (זו עם ה-id_number)
        full_record = next((r for r in records if r.get('id_number')), None)
        ghost_records = [r for r in records if not r.get('id_number')]

        # אם מצאנו רשומה מלאה, ננקה את ה"רפאים" שנוצרו אוטומטית
        if full_record and ghost_records:
            for ghost in ghost_records:
                requests.delete(f"{BASE44_API_URL}/entities/UserDevice/{ghost['id']}", headers=headers)
                print(f"Deleted duplicate ghost record for device: {d_id}")

        # עובדים על הרשומה המלאה בלבד
        user = full_record
        if not user or user.get('is_authorized') is True:
            continue

        id_number = user.get('id_number')
        secret_code = user.get('secret_code')

        if not secret_code:
            print(f"Skipping user {id_number} - No secret_code provided by app.")
            continue

        print(f"Authorizing User: {id_number}...")

        # 3. אישור המכשיר בטבלת UserDevice
        update_data = {"is_authorized": True}
        requests.put(f"{BASE44_API_URL}/entities/UserDevice/{user['id']}", headers=headers, json=update_data)

        # 4. הכנת המפתח המוצפן עבור טבלת AuthorizedKey
        # שים לב: השדה שונה ל-encrypted_payload לפי התיקון בבייס
        encrypted_val = xor_encrypt(MASTER_KEY, secret_code)
        
        key_payload = {
            "device_id": d_id,
            "encrypted_payload": encrypted_val 
        }

        # שליחת המפתח לטבלה הציבורית
        key_res = requests.post(f"{BASE44_API_URL}/entities/AuthorizedKey", headers=headers, json=key_payload)
        
        if key_res.status_code in [200, 201]:
            print(f"Success: Key issued for device {d_id}")
        else:
            print(f"Failed to issue key: {key_res.text}")

if __name__ == "__main__":
    sync_and_authorize()
