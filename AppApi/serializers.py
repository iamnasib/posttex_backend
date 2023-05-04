from rest_framework import serializers
from . models import Messages, Notifications, User, UserFeedback, UserVerification
from rest_framework.response import Response
from rest_framework import status
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate


class UserSerializer(serializers.HyperlinkedModelSerializer):
    email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())]
  )
    username = serializers.CharField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    avatar=serializers.ImageField(required=False)
    class Meta:
        model = User
        fields =  ['url','id' ,'full_name' ,'username' ,'email','avatar','date_joined',
                   'intro','website','mobile_number','is_private','is_verified','blocked_user','following','followers' ]
        
class ProtectedUserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields =  ['id' ,'full_name' ,'username' ,'avatar','date_joined',
                   'intro','website','is_private','is_verified' ]
    

class EditUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())]
  )
    username = serializers.CharField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    avatar=serializers.ImageField(required=False)
    class Meta:
        model = User
        fields =  ['id' ,'full_name' ,'username' ,'email','avatar',
                   'intro','website','mobile_number' ]

class PrivateAccountSerializer(serializers.ModelSerializer):
   class Meta:
        model = User
        fields = ['is_private']

class BlockedUsersSerializer(serializers.ModelSerializer):
    blocked_user = serializers.SerializerMethodField()
    blocked_by = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['blocked_user','blocked_by']

    def get_blocked_user(self, obj):
        request = self.context.get('request')
        return [
            {
                'id': user.id,
                'full_name': user.full_name,
                'username': user.username,
                'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
            } for user in obj.blocked_user.all()
        ]
    def get_blocked_by(self, obj):
        request = self.context.get('request')
        return [
            {
                'id': user.id,
                'full_name': user.full_name,
                'username': user.username,
                'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
            } for user in obj.blocked_by.all()
        ]
    
class UserVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserVerification
        fields = '__all__'

class UserFeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserFeedback
        fields = '__all__'

class FollowUnfollowSerializer(serializers.ModelSerializer):
    following = serializers.SerializerMethodField()
    followers = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['following','followers']
    def get_following(self, obj):
        request = self.context.get('request')
        return [
            {
                'id': user.id,
                'full_name': user.full_name,
                'username': user.username,
                'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
            } for user in obj.following.all()
        ]
    def get_followers(self, obj):
        request = self.context.get('request')
        return [
            {
                'id': user.id,
                'full_name': user.full_name,
                'username': user.username,
                'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
            } for user in obj.followers.all()
        ]

class FollowRequestsSerializer(serializers.ModelSerializer):
    requested_to = serializers.SerializerMethodField()
    requested_by = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['requested_to', 'requested_by']
    
    def get_requested_to(self, obj):
        request = self.context.get('request')
        return [
            {
                'id': user.id,
                'full_name': user.first_name,
                'username': user.username,
                'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
            } for user in obj.requested_to.all()
        ]
    def get_requested_by(self, obj):
        request = self.context.get('request')
        return [
            {
                'id': user.id,
                'full_name': user.first_name,
                'username': user.username,
                'avatar': request.build_absolute_uri(user.avatar.url) if user.avatar else None
            } for user in obj.requested_by.all()
        ]



class SearchSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    avatar=serializers.ImageField(required=False)
    class Meta:
        model = User
        fields =  ['id' ,'full_name' ,'username' ,'avatar' ]


class RegisterSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())]
  )
  username = serializers.CharField(
    required=True,
    validators=[UniqueValidator(queryset=User.objects.all())]
  )
  password = serializers.CharField(style={'input_type': 'password'},
    write_only=True, required=True, validators=[validate_password])
  password2 = serializers.CharField(style={'input_type': 'password'},write_only=True, required=True)
  class Meta:
    model = User
    fields = ('username', 'password', 'password2',
         'email', 'full_name')
    extra_kwargs = {
      'full_name': {'required': True}
    }

  def validate(self, attrs):
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError(
        {"password": "Password fields didn't match."})
    return attrs

  def create(self, validated_data):
    user = User.objects.create(
      username=validated_data['username'],
      email=validated_data['email'],
      full_name=validated_data['full_name']
    )
    user.set_password(validated_data['password'])
    user.save()
    return user

class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type': 'password'},write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(style={'input_type': 'password'},write_only=True, required=True)
    old_password = serializers.CharField(style={'input_type': 'password'},write_only=True, required=True)

    class Meta:
        model = User
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "Old password is not correct"})
        return "Old password is not correct"

    def update(self, instance, validated_data):

        instance.set_password(validated_data['password'])
        instance.save()

        return instance

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, write_only=True)
    password = serializers.CharField(style={'input_type': 'password'},
        trim_whitespace=False,write_only=True, required=True)

    def validate(self, attrs):
       
       username = attrs.get('username')
       password = attrs.get('password')
       if username and password:
          user = authenticate(request=self.context.get('request'), username=username,password=password)

          if not user:
            msg = 'Access denied: wrong username or password.'
            raise serializers.ValidationError(msg, code='authorization')
       else:
            msg = 'Both "username" and "password" are required.'
            raise serializers.ValidationError(msg, code='authorization')

        # We have a valid user, put it in the serializer's validated_data.
        # It will be used in the view.
       attrs['user'] = user
       return attrs

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Messages
        fields = ['id', 'sender', 'receiver', 'sent_date', 'textcontent','is_read']

class NotificationSerializer(serializers.ModelSerializer):
    notification_sender = ProtectedUserSerializer()
    notification_receiver = ProtectedUserSerializer()
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = Notifications
        fields = ['id', 'notification_sender', 'notification_receiver', 'verb', 'category', 'created_at', 'is_read', 'data','avatar_url']
    def get_avatar_url(self, obj):
        # Get the request object from the context
        request = self.context.get('request')

        # If the request is present, return the absolute URL of the avatar field
        if request:
            avatar_url = obj.notification_sender.avatar.url
            return request.build_absolute_uri(avatar_url)

        # If the request is not present, return the URL of the avatar field
        return obj.notification_sender.avatar.url
        
class StoreNotificationSerializer(serializers.ModelSerializer):
   
    class Meta:
        model = Notifications
        fields = ['id', 'notification_sender', 'notification_receiver', 'verb', 'category', 'created_at', 'is_read', 'data']