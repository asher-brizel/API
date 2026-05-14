import requests
import os
import base64

# הגדרות API
BASE44_API_URL = "https://kehilnet.base44.app/api"
MASTER_KEY = os.getenv("BASE44_MASTER_KEY")

headers = {
    "api_key": MASTER_KEY,
    "Content-Type": "application/json"
}

def xor_encrypt_to_base64(data, key):
    """ביצוע XOR וקידוד ל-Base64 כדי למנוע שיבוש תווים ב-JSON"""
    xor_result = bytearray([ord(data[i]) ^ ord(key[i % len(key)]) for i in range(len(data))])
    return base64.b64encode(xor_result).decode('utf-8')

def sync_and_authorize():
    print("--- Starting Secure Device Sync & Authorization ---")
    
    # 1. משיכת כל המכשירים הרשומים
    response = requests.get(f"{BASE44_API_URL}/entities/UserDevice", headers=headers)
    if response.status_code != 200:
        print(f"Error fetching devices: {response.text}")
        return

    devices = response.json()
    
    # מיפוי מכשירים לפי device_id לטיפול בכפילויות
    device_map = {}
    for device in devices:
        d_id = device.get('device_id')
        if d_id not in device_map:
            device_map[d_id] = []
        device_map[d_id].append(device)

    for d_id, records in device_map.items():
        # 2. ניקוי כפילויות: מחפשים רשומה עם ת.ז (id_number)
        full_record = next((r for r in records if r.get('id_number')), None)
        ghost_records = [r for r in records if not r.get('id_number')]

        if full_record and ghost_records:
            for ghost in ghost_records:
                requests.delete(f"{BASE44_API_URL}/entities/UserDevice/{ghost['id']}", headers=headers)
                print(f"Deleted orphan record for device: {d_id}")

        user = full_record
        # אם המכשיר כבר מאושר, אין צורך להנפיק מפתח שוב
        if not user or user.get('is_authorized') is True:
            continue

        id_number = user.get('id_number')
        secret_code = user.get('secret_code')

        if not secret_code:
            print(f"Skipping user {id_number} - Device hasn't sent secret_code yet.")
            continue

        print(f"Authorizing and Issuing Key for User: {id_number}...")

        # 3. אישור המכשיר בטבלה הראשית
        requests.put(f"{BASE44_API_URL}/entities/UserDevice/{user['id']}", 
                     headers=headers, 
                     json={"is_authorized": True})

        # 4. הכנת המפתח המוצפן (XOR + Base64)
        encrypted_val = xor_encrypt_to_base64(MASTER_KEY, secret_code)
        
        # 5. ניקוי מפתחות ישנים של המכשיר הזה (אם קיימים) כדי למנוע כפילויות ב-AuthorizedKey
        old_keys = requests.get(f"{BASE44_API_URL}/entities/AuthorizedKey?q={{\"device_id\":\"{d_id}\"}}", headers=headers).json()
        for old_key in old_keys:
            requests.delete(f"{BASE44_API_URL}/entities/AuthorizedKey/{old_key['id']}", headers=headers)

        # 6. שליחת המפתח החדש
        key_payload = {
            "device_id": d_id,
            "encrypted_payload": encrypted_val 
        }

        key_res = requests.post(f"{BASE44_API_URL}/entities/AuthorizedKey", headers=headers, json=key_payload)
        
        if key_res.status_code in [200, 201]:
            print(f"Success: Secure key issued for device {d_id}")
        else:
            print(f"Failed to issue key: {key_res.text}")

if __name__ == "__main__":
    sync_and_authorize()
