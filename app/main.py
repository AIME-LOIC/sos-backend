from fastapi import FastAPI
from app.database import engine, Base
from app.routes import users, sos

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SOS Emergency Backend")

app.include_router(users.router, prefix="/users")
app.include_router(sos.router, prefix="/sos")

@app.get("/")
def health():
    return {"status": "running"}
