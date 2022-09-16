from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.homepage, name="home"),

   # Login page
    path('login', views.login_user, name="login"),

    # Register new user page
    path('register', views.register_user, name="register"),

    # logout from homepage
    path('logout', views.logout_user),

    # User Profile display page
    path('profile', views.profile, name="profile"),

    #admin page
    path('admins/users', views.get_users),
    path('admins/admins', views.get_admins),
    path('promote_user/<int:user_id>', views.promote_user),
    path('demote_user/<int:user_id>', views.demote_user),
    path('admins/users', views.add_users),
    path('add_admins/', views.add_admin),
    path('delete_user/<int:user_id>', views.delete_user),
    path('delete_admin/<int:user_id>', views.delete_admin),

    # Change password
    path('password_change', auth_views.PasswordChangeView.as_view(
        template_name='accounts/password_change.html')),
    path('password_change_done', auth_views.PasswordChangeView.as_view(
        template_name='accounts/password_change_done.html'), name='password_change_done'),

    # Reset password when you forget
    path('reset_password/', auth_views.PasswordResetView.as_view(
        template_name='accounts/password_reset.html'), name='reset_password'),
    path('reset_email_sent/', auth_views.PasswordResetDoneView.as_view(
        template_name='accounts/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='accounts/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset_complete/', auth_views.PasswordResetCompleteView.as_view(
        template_name='accounts/password_reset_complete.html'), name='password_reset_complete'),
]
