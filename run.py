from __future__ import annotations

import os

import uvicorn
from dotenv import load_dotenv


if __name__ == "__main__":
    load_dotenv(override=False)
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
