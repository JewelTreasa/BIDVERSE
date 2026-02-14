from django.urls import path, include
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # API endpoints (existing)
    path('register/', views.RegisterAPIView.as_view(), name='api-register'),
    path('login/', views.LoginAPIView.as_view(), name='api-login'),
    path('google/', views.GoogleLoginAPIView.as_view(), name='api-google-login'),
    path('password-reset-request/', views.PasswordResetRequestView.as_view(), name='api-password-reset-request'),
    path('password-reset-confirm/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='api-password-reset-confirm'),

    # Web form endpoints (new)
    path('login/', views.login_user, name='login'),
    path('register/', views.register_user, name='register'),
    path('logout/', views.logout_user, name='logout'),
    path('check-auth/', views.check_auth_status, name='check_auth'),
    
    # Membership - Moved to bidverse/urls.py
    # path('membership/', views.membership_plans, name='membership_plans'),
    # path('membership/purchase/<str:plan_type>/', views.purchase_membership, name='purchase_membership'),
    
    path('checkout/<int:listing_id>/', views.checkout_auction, name='checkout_auction'),


    # Google OAuth
    path('oauth/', include('social_django.urls', namespace='social')),

    # Password reset (Django built-in)
    path('password-reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),

    # Reminder Email
    path('reminder/send/<int:listing_id>/', views.send_reminder_email, name='send_reminder_email'),

    # Payment Callback
    path('payment/success/', views.payment_success, name='payment_success'),

    # Settings
    path('settings/', views.settings_view, name='settings'),
    
    # Chatbot
    path('chatbot/message/', views.chatbot_message, name='chatbot_message'),
]
