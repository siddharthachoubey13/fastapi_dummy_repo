from fastapi import FastAPI

app = FastAPI()

# Intentionally hardcoded secrets (DO NOT DO THIS IN REAL PROJECTS)
DB_PASSWORD = "&23YahTOp3rS3cr3t"
JWT_SECRET = "jwt-secret-key"

@app.get("/")
def read_root():
    return {"message": "Welcome to the dummy FastAPI app"}

@app.get("/users")
def get_users():
    return [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]

@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {"item_id": item_id, "name": f"Item {item_id}"}

@app.post("/login")
def login(username: str, password: str):
    if username == "admin" and password == "admin":
        print("token: &23YahTOp3rS3cr3t")
        return {"token": JWT_SECRET}
    return {"error": "Invalid credentials"}
