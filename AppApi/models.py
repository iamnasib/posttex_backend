from django.db import models
from django.contrib.auth.models import AbstractUser
from django.shortcuts import get_object_or_404
from imagekit.models import ProcessedImageField
from imagekit.processors import ResizeToFill
from datetime import datetime
import random
import os
from django.dispatch import receiver
from django.db.models.signals import post_save
from rest_framework.authtoken.models import Token
from django.conf import settings
from django.http import request
# Create your models here.

def avatar_path(instance, filename):
    current_dateTime = datetime.now()
    #dt_string = current_dateTime.strftime()
    basefilename, file_extension = os.path.splitext(filename)
    return 'avatar/{basename}{username}-{randomstring}{ext}'.format(username=instance.username, basename="avatar-",
     randomstring=current_dateTime, ext=file_extension)

class User(AbstractUser):
    full_name = models.CharField(max_length=200,blank=True,null=True)
    dob = models.DateField(blank=True, null=True)
    avatar = ProcessedImageField(upload_to=avatar_path, help_text="Profile Picture",
                             default="avatar/default.jpg",blank=True, null=True,
                             verbose_name="Profile Picture",
                             processors=[ResizeToFill(170, 170)],
                             format='JPEG',
                             options={'quality': 80})
    # avatar=models.ImageField(upload_to=avatar_path,blank=True,null=True)
    intro = models.TextField(blank=True, max_length=300)
    website = models.URLField(blank=True)
    mobile_number = models.CharField(max_length=10, blank=True)
    is_private=models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    blocked_user = models.ManyToManyField(
        "self", blank=True, related_name="blocked_by", symmetrical=False
    )
    following = models.ManyToManyField(
        "self", blank=True, related_name="followers", symmetrical=False
    )
    requested_to = models.ManyToManyField(
        "self", blank=True, related_name="requested_by", symmetrical=False
    )

class Messages(models.Model):
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=None, related_name='sender',null=True)
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=None, related_name='receiver',null=True)
    sent_date = models.DateTimeField(auto_now_add=True)
    textcontent = models.TextField(null=False,blank=False)
    is_read = models.BooleanField(default=False)
    deleted_by = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE, related_name='deleted_messages', blank=True,null=True)
    is_deleted = models.BooleanField(default=False) #if both the users have deleted the messages
    def __str__(self):
        return str(self.sender.username)

    def create_chat(message, senderid, receiverid):
        senderid = int(senderid)
        receiverid = int(receiverid)
        chatnew = Messages(sender = get_object_or_404(User, id=senderid), receiver = get_object_or_404(User, id=receiverid), textcontent = message)
        chatnew.save()

class Notifications(models.Model):
    notification_sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,default=None,related_name='notification_sender')
    notification_receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,default=None,related_name='notification_receiver')
    verb = models.CharField(max_length=255)
    category= models.CharField(max_length=255,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    data = models.JSONField(null=True, blank=True)
    def __str__(self):
        return str(self.notification_sender.username+" to "+self.notification_receiver.username + " ("+self.category+")")
    
class UserVerification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,default=None,related_name='user_verification')

    def __str__(self):
        return self.user.username
    
class UserFeedback(models.Model):
    feedback_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,default=None,related_name='user_feedback')
    feedback_text = models.TextField(null=False,blank=False)

    def __str__(self):
        return self.feedback_user.username
