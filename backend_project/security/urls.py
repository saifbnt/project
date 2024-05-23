from django.urls import path
from .views import UserRegister, UserLogin, UserLogout, UserView, AdminUserManagement, UserDetailView

urlpatterns = [
    path('register/', UserRegister.as_view(), name='register'),
    path('login/', UserLogin.as_view(), name='login'),
    path('logout/', UserLogout.as_view(), name='logout'),
    path('user/', UserDetailView.as_view(), name='user_detail'),  # Ajouté pour les détails de l'utilisateur
    path('admin/users/', AdminUserManagement.as_view(), name='admin_users'),
    path('admin/users/<int:user_id>/', AdminUserManagement.as_view(), name='admin_user_detail'),
]
