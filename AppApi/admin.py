from django.contrib import admin
from .models import User,Notifications, UserFeedback, UserVerification
from .models import Messages
# Register your models here.

admin.site.register(User)
admin.site.register(Messages)
admin.site.register(Notifications)
admin.site.register(UserVerification)
admin.site.register(UserFeedback)
from rest_framework.authtoken.admin import TokenAdmin

TokenAdmin.raw_id_fields = ['user']