from channels.generic.websocket import AsyncWebsocketConsumer
import json 
from .models import User
class SearchConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.send(text_data=json.dumps({
            'users': []
        }))

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        search_term = json.loads(text_data)['search_term']
        users = User.objects.filter(username__contains=search_term).values('username')
        await self.send(text_data=json.dumps({
            'users': list(users)
        }))