import ast
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import renderers, views, viewsets, permissions, generics,status
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view,permission_classes
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from rest_framework.authtoken.models import Token
from knox.models import AuthToken
from knox.views import LogoutView
from knox.auth import TokenAuthentication
from rest_framework.parsers import MultiPartParser,FormParser,FileUploadParser,JSONParser
from rest_framework.views import APIView
from django.db.models import Q
from django.contrib.auth import login,logout
from django.views.decorators.csrf import csrf_exempt
from django.core import serializers
import json
from .serializers import (BlockedUsersSerializer, FollowRequestsSerializer, MessageSerializer, NotificationSerializer, ProtectedUserSerializer, SearchSerializer, StoreNotificationSerializer, UserFeedbackSerializer, UserSerializer,RegisterSerializer,
                          LoginSerializer, ChangePasswordSerializer,PrivateAccountSerializer,EditUserSerializer,FollowUnfollowSerializer, UserVerificationSerializer)
from .permissions import IsOwnerOrReadOnly,IsOwner
from .models import Messages, Notifications, User, UserVerification




# Create your views here.



class UserViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list`, `create`, `retrieve`,
    `update` and `destroy` actions.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly,
                          IsOwnerOrReadOnly]
    parser_classes = (MultiPartParser, FormParser)
    
class EditUserView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly,]
    serializer_class = EditUserSerializer
    parser_classes = (MultiPartParser, FormParser)

class UserDetailView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly,]
    serializer_class = UserSerializer
    def get_object(self):
        username = self.kwargs.get("username")
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            raise Http404("User does not exist")
            
class PrivateAccountView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly,]
    serializer_class = PrivateAccountSerializer
    parser_classes = (MultiPartParser, FormParser)
    
class BlockedUsersView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    serializer_class = BlockedUsersSerializer

@csrf_exempt
@api_view(['GET','PUT'])
def blockUser(request,pk):
    data = request.data
    user_profile = User.objects.get(id=data['blocked_user'])
    print('hii',data)
    current_user = User.objects.get(id=pk)
    blocked = True
    if user_profile in current_user.blocked_user.all():
        current_user.blocked_user.remove(user_profile.id)
        blocked = False
    else:
        user_profile.following.remove(current_user.id)
        user_profile.followers.remove(current_user.id)
        user_profile.requested_by.remove(current_user.id)
        user_profile.requested_to.remove(current_user.id)
        current_user.blocked_user.add(user_profile.id)
    resp = {
        'blocked': blocked,
    }
    response = json.dumps(resp)
    return HttpResponse(response, content_type="application/json")

class ChatViewSet(viewsets.ModelViewSet):
    queryset = Messages.objects.all()
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

class UserVerificationCreateView(generics.CreateAPIView):
    serializer_class = UserVerificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        if UserVerification.objects.filter(user=user).exists():
            return Response({"status": False})
        user_verification = UserVerification.objects.create(user=user)
        serializer = self.get_serializer(user_verification)
        return Response( {"status":True})
    
class UserFeedbackCreateView(generics.CreateAPIView):
    serializer_class = UserFeedbackSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(feedback_user=user)
        return Response( {"status":True})

    
class FollowToggleUserView(generics.GenericAPIView):
    queryset = User.objects.all()

    def post(self, request, pk):
        try:
            user_to_follow = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        
        user = request.user
        following=False
        if user == user_to_follow:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={"detail": "You can't follow yourself"})
        
        if user.following.filter(pk=user_to_follow.pk).exists():
            user.following.remove(user_to_follow)
            return Response(status=status.HTTP_201_CREATED,data={'toggle':following})
        else:
            if user_to_follow.is_private:
                if user.requested_to.filter(pk=user_to_follow.pk).exists():
                    user.requested_to.remove(user_to_follow)
                    return Response(status=status.HTTP_201_CREATED,data={'toggle':'deleted'})
                else:
                    # Add a follow request to the requested_to field
                    user.requested_to.add(user_to_follow)
                    requested=True
                    return Response(status=status.HTTP_201_CREATED, data={"toggle": 'requested'})
            else:
                user.following.add(user_to_follow)
                following=True
                return Response(status=status.HTTP_201_CREATED,data={'toggle':following})

class RemoveFollowerView(generics.GenericAPIView):
    queryset = User.objects.all()
    def post(self, request, pk):
        try:
            user_to_remove = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        
        user = request.user
        removed=True
        if user == user_to_remove:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={"detail": "You can't remove yourself"})
        
        if user.followers.filter(pk=user_to_remove.pk).exists():
            user.followers.remove(user_to_remove)
            return Response(status=status.HTTP_201_CREATED,data={'removed':removed})
        else:
            user.followers.add(user_to_remove)
            removed=False
            return Response(status=status.HTTP_201_CREATED,data={'removed':removed})

            
class FollowUsersListView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    serializer_class = FollowUnfollowSerializer

class FollowRequestsView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    serializer_class = FollowRequestsSerializer
    def get_serializer_context(self):
        return {'request': self.request}

class AcceptFollowRequestView(APIView):
    def put(self, request, user_id):
        # Get the authenticated user
        current_user = request.user
        
        # Get the user who sent the follow request
        follow_request_user = User.objects.get(id=user_id)
        
        # Add the user to the authenticated user's followers
        if follow_request_user in  current_user.requested_by.all():
            current_user.followers.add(follow_request_user)
            accepted=True
            # Remove the follow request
            current_user.requested_by.remove(follow_request_user)
        else:
            return Response(status=status.HTTP_204_NO_CONTENT)
        
        return Response(status=status.HTTP_200_OK,data={accepted})
    
class DeleteFollowRequestView(APIView):
    def put(self, request, user_id):
        # Get the authenticated user
        current_user = request.user
        
        # Get the user who sent the follow request
        follow_request_user = User.objects.get(id=user_id)
        deleted=True
        # Remove the follow request
        current_user.requested_by.remove(follow_request_user)
        
        return Response(status=status.HTTP_200_OK,data={deleted})



@csrf_exempt
def create_new_chat(request):
    if request.method == "POST":
        
        querydictstr = request.body.decode('UTF-8')
        querydict = ast.literal_eval(querydictstr)
        Messages.create_chat(querydict['textcontent'], querydict['sender'], querydict['receiver'])
    return HttpResponse('{ "name":"John", "age":30, "city":"New York"}')

class ChatDetailView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = MessageSerializer
    def get_queryset(self):        
        return Messages.objects.filter(Q(sender=self.request.user.id,
        receiver=self.kwargs['receiverId']) | Q(sender=self.kwargs['receiverId'],receiver=self.request.user.id)
        ).exclude(Q(deleted_by=self.request.user.id) | Q (is_deleted=True)).order_by('sent_date')

class RecentChatsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = self.request.user
        messages = Messages.objects.filter(Q(sender=user) | Q(receiver=user)
                                           ).exclude(Q(deleted_by=user.id) | Q (is_deleted=True)).order_by('-sent_date')

        recent_chats = set()
        for message in messages:
            if message.sender == user:
                recent_chats.add(message.receiver)
            else:
                recent_chats.add(message.sender)

        recent_chats_data = []
        for chat in recent_chats:
            chat_messages = messages.filter(Q(sender=user, receiver=chat) | Q(sender=chat, receiver=user)
                                            )
            unread_messages=chat_messages.filter(is_read=False).count()
            
            last_message = chat_messages.first()
            is_read = last_message.is_read

            chat_data = {
                'receiver':last_message.receiver.username,
                'username': chat.username,
                'last_message': last_message.textcontent if last_message else '',
                'avatar': request.build_absolute_uri(chat.avatar.url) if chat.avatar else '',
                'last_message_sent_date': last_message.sent_date if last_message else None,
                'is_read': is_read,
                'unread_msgs':unread_messages

            }
            recent_chats_data.append(chat_data)
            # sort the chats based on the last message sent/received date
        recent_chats_data.sort(key=lambda x: x['last_message_sent_date'], reverse=True)

        return Response({'recent_chats': recent_chats_data})

class MarkMessagesAsReadView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        data = json.loads(request.body)
        user_id = data.get('user_id')
        current_user = request.user
        userID=User.objects.get(username=user_id)
        messages = Messages.objects.filter(sender=userID.id, receiver=current_user).update(is_read=True)
        # messages.update(is_read=True)

        return Response({'status': 'success'})

class MarkChatAsDeletedView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        user = request.user
        receiver_id = request.data
        msgs=Messages.objects.filter(
            Q(sender=user, receiver=receiver_id) | Q(sender=receiver_id, receiver=user)
        )
        if msgs.filter(deleted_by__isnull=True).exists():

            # Update the deleted_by field for all messages exchanged between the sender and receiver
            msgs.update(deleted_by=user)
        else:
            msgs.update(is_deleted=True)

        return Response({'status': 'success'})

class UnreadMessagesBadge(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self,request):
        current_user=request.user
        # Get all unread messages for the current user
        unread_messages = Messages.objects.filter(receiver=current_user, is_read=False)

        # Count the number of unique senders among the unread messages
        unique_senders = unread_messages.values('sender').distinct().count()

        # The badge number would be the count of unique senders
        badge_number = unique_senders
        return Response({'badge_number': badge_number})
    # def post(self, request):
    #     user = request.user
    #     receiver_id=request.data

    #     # Get the messages exchanged between the sender and receiver
    #     messages = Messages.objects.filter(sender=user, receiver=receiver_id) | Messages.objects.filter(sender=receiver_id, receiver=user)

    #     # Update the deleted_by field for each message to the user who initiated the deletion
    #     messages.update(deleted_by= [user])
    #     # for message in messages:
    #     #     message.deleted_by.add(user)

    #     return Response({'status': 'success'})

class NotificationsView(generics.ListAPIView):
    def get(self, request):
        notifications = Notifications.objects.filter(notification_receiver=request.user).order_by('-created_at')[:20]
        serializer = NotificationSerializer(notifications, many=True,context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = StoreNotificationSerializer(data=request.data)
        if serializer.is_valid():
            notification = serializer.save()
            return Response({'status': 'success'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request):
        sender = request.data.get('notification_sender')
        print(request.data)
        receiver = request.data.get('notification_receiver')
        verb = request.data.get('verb')
        notifications=Notifications.objects.filter(notification_sender=sender, notification_receiver=receiver, verb=verb)
        for notification in notifications:
            notification.delete()
        return Response(status=status.HTTP_201_CREATED,data={"deleted"})

class UnreadNotificationsLengthView(generics.ListAPIView):
    serializer_class = NotificationSerializer

    def get_queryset(self):
        return Notifications.objects.filter(notification_receiver=self.request.user, is_read=False)
    
class MarkAllNotificationsAsReadView(APIView):
    def post(self, request):
        # Get the current user
        user = request.user

        # Update all the notifications to mark them as read
        Notifications.objects.filter(notification_receiver=user).update(is_read=True)

        return Response({'status': 'success'})

        # return unread_notifications.count()
#     permission_classes = (IsAuthenticated,)
#     serializer_class = NotificationSerializer
#     def get_queryset(self):
#         user = self.request.user
#         return Notifications.objects.filter(notification_receiver=user).order_by('-created_at')[:20]

class DeleteNotificationView(APIView):
    def post(self, request):
            sender = request.data.get('notification_sender')
            print(request.data)
            receiver = request.data.get('notification_receiver')
            verb = request.data.get('verb')
            notifications=Notifications.objects.filter(notification_sender=sender, notification_receiver=receiver, verb=verb).delete()
            # for notification in notifications:
            #     notification.delete()
            return Response(status=status.HTTP_201_CREATED,data={'deleted'})

class RegisterUserView(generics.CreateAPIView):
  permission_classes = (AllowAny,)
  serializer_class = RegisterSerializer
  def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            
        })

class LoginView(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer
    def post(self,request, *args, **kwargs):
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        
        return Response({"token": AuthToken.objects.create(user)[1],'id': user.pk,
            'username': user.username}, status=status.HTTP_202_ACCEPTED)

class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,IsOwner)
    serializer_class = ChangePasswordSerializer

class SearchView(generics.ListAPIView):
    serializer_class = SearchSerializer

    def get_queryset(self):
        username = self.request.query_params.get('username', None)
        if username:
            return User.objects.filter(Q(username__contains=username) | Q(full_name__contains=username)).exclude(Q(blocked_by=self.request.user) | Q(blocked_user=self.request.user))
        return None

# class UserLogoutView(LogoutView):
#   authentication_classes = (TokenAuthentication,)
#   permission_classes = (IsAuthenticated,)
#   def post(self, request, format=None):
#         request._auth.delete()
#         logout(request)
#         return Response(None, status=status.HTTP_204_NO_CONTENT)