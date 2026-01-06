from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView
from django.contrib.auth import views as auth_views
from accounts import views as account_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),

    # Frontend routes
    path('', TemplateView.as_view(template_name='index.html'), name='home'),
    path('contact/', TemplateView.as_view(template_name='contact.html'), name='contact'),
    path('dashboard/', account_views.dashboard, name='dashboard'),

    # Web form views (outside of API namespace)
    path('login/', account_views.login_user, name='login'),
    path('register/', account_views.register_user, name='register'),
    path('logout/', account_views.logout_user, name='logout'),
    path('forgot-password/', auth_views.PasswordResetView.as_view(template_name='registration/password_reset_form.html'), name='forgot_password'),

    # Password reset URLs (Custom views with BidVerse templates)
    path('password-reset/', account_views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', account_views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', account_views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', account_views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    # Serve static assets from the root assets directory
    urlpatterns += static('/assets/', document_root=settings.BASE_DIR.parent / 'assets')

