from fastapi import FastAPI
from dotenv import load_dotenv
load_dotenv()
from app.api.auth import router as auth_router
from app.core.database import Base, engine
from app.models.db_models import User
from sqlalchemy import text

app = FastAPI()
app.include_router(auth_router)

@app.on_event("startup")
def startup_event():
    # Create tables
    try:
        Base.metadata.create_all(bind=engine)
        # Test DB connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("✅ Database connection and table creation successful!")
    except Exception as e:
        print(f"❌ Database connection/table creation failed: {e}")
        raise

@app.get("/")
async def root():
    return {"message": "AI Happiness Companion Backend is running!"}
