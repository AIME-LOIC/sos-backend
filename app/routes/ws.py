from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import List, Dict
from app.auth import get_current_user
from app.models import User

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        # track websocket and associated user
        self.active_connections: List[Dict] = []

    async def connect(self, websocket: WebSocket, user: User):
        await websocket.accept()
        self.active_connections.append({"ws": websocket, "user": user})

    def disconnect(self, websocket: WebSocket):
        self.active_connections = [
            conn for conn in self.active_connections if conn["ws"] != websocket
        ]

    async def broadcast(self, message: dict):
        for conn in self.active_connections:
            user = conn["user"]
            # Admin sees all, normal users see only their own alerts
            if user.role == "admin" or message["user_id"] == str(user.id):
                await conn["ws"].send_json(message)

manager = ConnectionManager()
@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket, current_user=Depends(get_current_user)):
    await manager.connect(websocket, current_user)
    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)
