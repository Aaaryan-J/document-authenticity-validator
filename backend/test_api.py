import requests

BASE_URL = "http://localhost:5000/api"
session = requests.Session()

# ========== HELPERS ==========
def print_step(title):
    print(f"\n=== {title} ===")

def safe_json(res):
    try:
        return res.json()
    except ValueError:
        return {"raw_response": res.text}

# ========== AUTH ==========
def register_admin():
    print_step("Registering admin user")
    res = session.post(f"{BASE_URL}/auth/register", json={
        "username": "adminuser",
        "password": "admin123",
        "email": "admin@test.com",
        "role": "admin"
    })
    print("Register response:", res.status_code, safe_json(res))
    return res

def login_admin():
    print_step("Logging in as admin")
    res = session.post(f"{BASE_URL}/auth/login", json={
        "username": "adminuser",
        "password": "admin123"
    })
    print("Login response:", res.status_code, safe_json(res))
    return res

# ========== INSTITUTION ==========
def register_institution():
    print_step("Registering new institution")
    res = session.post(f"{BASE_URL}/auth/institution/register", json={
        "name": "Test University",
        "code": "TESTUNI01",
        "address": "123 Test Street",
        "email": "contact@testuni.com",
        "phone": "1234567890",
        "website": "https://testuni.com"
    })
    print("Institution response:", res.status_code, safe_json(res))
    return res

def approve_institution(inst_id, token):
    print_step("Approving institution")
    res = session.post(
        f"{BASE_URL}/auth/institutions/{inst_id}/approve",   # ✅ fixed URL (removed duplicate /api)
        headers={"Authorization": f"Bearer {token}"},
        json={"action": "approve"}
    )
    print("Approval response:", res.status_code, safe_json(res))  # ✅ safe_json
    return res

# ========== MAIN RUN ==========
if __name__ == "__main__":
    # 1. Register admin
    register_admin()

    # 2. Login admin
    login_res = login_admin()
    data = safe_json(login_res)
    if "access_token" not in data:
        print(" Admin login failed, stopping.")
        exit(1)
    admin_token = data["access_token"]

    # 3. Register institution
    inst_res = register_institution()
    inst_data = safe_json(inst_res)
    if inst_res.status_code == 201:
        inst_id = inst_data["institution"]["id"]
    else:
        # fallback: handle existing institution
        inst_id = inst_data.get("institution", {}).get("id", 1)

    # 4. Approve institution
    approve_institution(inst_id, admin_token)
