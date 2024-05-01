from django.urls import path
from . import views
from .views import SQLInjectionTest,NoSQLMapScan,XSSerScan

urlpatterns = [
	path('register', views.UserRegister.as_view(), name='register'),
	path('login', views.UserLogin.as_view(), name='login'),
	path('logout', views.UserLogout.as_view(), name='logout'),
	path('user', views.UserView.as_view(), name='user'),
    path('sql_injection_test/', SQLInjectionTest.as_view(), name='sql_injection_test'),  # Utilisez la nouvelle vue
    path('sqlmap_scan/', NoSQLMapScan.as_view(), name='sqlmap_scan'),
    path('XSSerScan/', XSSerScan.as_view(), name='sqlmap_scan'),




    
]

