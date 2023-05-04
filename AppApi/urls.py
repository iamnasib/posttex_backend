from django.urls import path,include
from AppApi import views
from . import consumers
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (DeleteNotificationView, MarkMessagesAsReadView, PrivateAccountView, RegisterUserView,LoginView,ChangePasswordView, RemoveFollowerView, SearchView,ChatDetailView, 
                    UserDetailView, BlockedUsersView, RecentChatsView,MarkChatAsDeletedView,EditUserView,FollowToggleUserView,
                    FollowUsersListView,FollowRequestsView,AcceptFollowRequestView,DeleteFollowRequestView,
                    NotificationsView,UnreadNotificationsLengthView,MarkAllNotificationsAsReadView,UnreadMessagesBadge, UserFeedbackCreateView, UserVerificationCreateView)
from django.contrib.auth.views import LogoutView
from knox import views as knox_views
from rest_framework import urls
from django.conf import settings
from django.conf.urls.static import static
# Create a router and register our viewsets with it.
router = DefaultRouter()
# router.register(r'snippets', views.SnippetViewSet,basename="snippet")
router.register(r'users', views.UserViewSet,basename="user")
router.register(r'chats', views.ChatViewSet,basename="chat")

# The API URLs are now determined automatically by the router.
urlpatterns =  [
    path('', include(router.urls)),
    path('api/register', RegisterUserView.as_view(),name="register"),
    path('api/login', LoginView.as_view(),name="login"),
    path('api/logout', knox_views.LogoutView.as_view(), name='logout'),
    path('api/change-password/<int:pk>', ChangePasswordView.as_view(),name="change_password"),
    path('api/edit-user/<int:pk>', EditUserView.as_view(),name="edit-user"),
    path('chat/createchat/', views.create_new_chat, name='create_chat'),
    path('api/search/', SearchView.as_view(), name='search'),
    path('api/chat/<int:receiverId>', ChatDetailView.as_view(), name='chat-detail'),
    path('api/recent-chat', RecentChatsView.as_view(), name='recent-chat'),
    path('api/delete-chat', MarkChatAsDeletedView.as_view(), name='delete-chat'),
    path('api/user/<str:username>', UserDetailView.as_view(), name='user-detail'),
    path('api/private-account/<int:pk>', PrivateAccountView.as_view(), name='private-account'),
    path('api/blocked-users/<int:pk>', BlockedUsersView.as_view(), name='blocked-users'),
    path('api/block-user/<int:pk>', views.blockUser, name='block-user'),
    path('api/follow-toggle/<int:pk>', FollowToggleUserView.as_view(), name='follow-toggle'),
    path('api/remove-follower/<int:pk>', RemoveFollowerView.as_view(), name='remove-follower'),
    path('api/follow-users-list/<int:pk>', FollowUsersListView.as_view(), name='follow-users-list'),
    path('api/follow-requests-list/<int:pk>', FollowRequestsView.as_view(), name='follow-requests-list'),
    path('api/accept-follow-request/<int:user_id>', AcceptFollowRequestView.as_view(), name='accept-follow-request'),
    path('api/delete-follow-request/<int:user_id>', DeleteFollowRequestView.as_view(), name='delete-follow-request'),
    path('api/notifications', NotificationsView.as_view(), name='notifications'),
    path('api/notifications/del', DeleteNotificationView.as_view(), name='delete-notification'),
    path('api/unread-notifications-length', UnreadNotificationsLengthView.as_view(), name='unread-notifications-length'),
    path('api/mark-notifications-asread', MarkAllNotificationsAsReadView.as_view(), name='mark-notifications-asread'),
    path('api/mark-messages-as-read', MarkMessagesAsReadView.as_view(), name='mark-messages-as-read'),
    path('api/unread-messages-badge', UnreadMessagesBadge.as_view(), name='unread-messages-badge'),
    path('api/request-verification', UserVerificationCreateView.as_view(), name='request-verification'),
    path('api/send-feedback', UserFeedbackCreateView.as_view(), name='send-feedback'),
    
]

#url(r'^polls/(?P<string>[\w\-]+)/$','polls.views.detail')
#python manage.py runserver_plus --cert-file cert.pem --key-file key.pem 192.168.29.48:8000
#ng serve --host 192.168.29.48
#EA3F9B hex

urlpatterns += [
    path('api-auth/', include('rest_framework.urls')),
]
if settings.DEBUG:
  urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
