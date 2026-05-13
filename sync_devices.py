import requests
import os
import base64

# הגדרות מתוך GitHub Secrets
BASE44_API_URL = "https://kehilnet.base44.app/api"
BASE44_API_KEY = os.environ.get("BASE44_MASTER_KEY")
SUPABASE_URL = "https://gcwvbfnysbazxtfelems.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imdjd3ZiZm55c2Jhenh0ZmVsZW1zIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTYzODUxNDIsImV4cCI6MjA3MTk2MTE0Mn0.uHxqP9QDRpPOgeHCbKSsvu6AFVb3LhYoTb7ljAlDfjI"

def xor_cipher(data, key):
    """מצפין/מפענח מחרוזת באמצעות XOR - פתרון קל ומאובטח להעברת המפתח"""
    return base64.b64encode(''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)).encode()).decode()

def run_verification():
    headers_b44 = {"api_key": BASE44_API_KEY, "Content-Type": "application/json"}
    
    # 1. משיכת רשימת הממתינים מ-Base44
    query = '{"is_authorized": false}'
    resp = requests.get(f"{BASE44_API_URL}/entities/UserDevice?q={query}", headers=headers_b44)
    
    if resp.status_code != 200:
        return

    pending_users = resp.json()
    if not isinstance(pending_users, list):
        return

    for user in pending_users:
        m_z = user.get("id_number")
        phone = user.get("phone_number")
        device_id = user.get("device_id")
        secret_code = user.get("secret_code") # הקוד שהאפליקציה ייצרה
        
        if not all([m_z, phone, device_id, secret_code]):
            continue

        # 2. אימות מול Supabase (Double Login)
        login_url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
        login_payload = {"email": f"{m_z}@gmail.com", "password": phone}
        sb_headers = {"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"}
        
        login_resp = requests.post(login_url, json=login_payload, headers=sb_headers)

        if login_resp.status_code == 200:
            # 3. הצפנת מפתח המאסטר באמצעות ה-SecretCode של המכשיר
            encrypted_payload = xor_cipher(BASE44_API_KEY, secret_code)

            # 4. יצירת רשומת המפתח המוצפן ב-AuthorizedKey
            key_payload = {
                "device_id": device_id,
                "api_key_value": encrypted_payload # השדה שונה ל-encrypted_payload בתיקון האחרון
            }
            requests.post(f"{BASE44_API_URL}/entities/AuthorizedKey", json=key_payload, headers=headers_b44)

            # 5. עדכון סטטוס המכשיר למאושר
            requests.put(f"{BASE44_API_URL}/entities/UserDevice/{user['id']}", 
                         json={"is_authorized": True}, headers=headers_b44)
            print(f"User {m_z} authorized and key issued.")

if __name__ == "__main__":
    run_verification()
