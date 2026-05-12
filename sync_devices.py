import requests
import os

# נתונים מה-CURL שלך
SUPABASE_URL = "https://gcwvbfnysbazxtfelems.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imdjd3ZiZm55c2Jhenh0ZmVsZW1zIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTYzODUxNDIsImV4cCI6MjA3MTk2MTE0Mn0.uHxqP9QDRpPOgeHCbKSsvu6AFVb3LhYoTb7ljAlDfjI"

BASE44_API_URL = "https://kehilnet.base44.app/api"
BASE44_API_KEY = os.environ.get("BASE44_MASTER_KEY")

def run_verification():
    headers_b44 = {"api_key": BASE44_API_KEY, "Content-Type": "application/json"}
    
    # 1. משיכת רשימת הממתינים מ-Base44
    query = '{"is_authorized": false}'
    resp = requests.get(f"{BASE44_API_URL}/entities/UserDevice?q={query}", headers=headers_b44)
    pending_users = resp.json()

    for user in pending_users:
        m_z = user.get("id_number")
        phone = user.get("phone_number")
        
        if not m_z or not phone:
            continue

        # 2. ניסיון לוגין מול Supabase כדי לוודא את הפרטים
        login_url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
        login_payload = {
            "email": f"{m_z}@gmail.com", # לפי הפורמט שראינו
            "password": phone
        }
        sb_headers = {"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"}
        
        login_resp = requests.post(login_url, json=login_payload, headers=sb_headers)

        # 3. אם הלוגין הצליח (200), המשתמש דובר אמת
        if login_resp.status_code == 200:
            user_data = login_resp.json()
            # מוודאים שקיבלנו אובייקט משתמש תקין
            if "user" in user_data:
                print(f"Verified successfully: {m_z}")
                # עדכון הסטטוס ב-Base44 ל-True
                requests.put(
                    f"{BASE44_API_URL}/entities/UserDevice/{user['id']}",
                    json={"is_authorized": True},
                    headers=headers_b44
                )
        else:
            print(f"Failed to verify {m_z}. Supabase status: {login_resp.status_code}")

if __name__ == "__main__":
    run_verification()
