from django.urls import path
from django.contrib.auth.views import LogoutView
from .views import register, user_login, reclamation

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', user_login, name='login'),
    path('reclamation/', reclamation, name='reclamation'),
    path('logout/', LogoutView.as_view(), name='logout'),  # Ensure the 'name' is 'logout'
]
