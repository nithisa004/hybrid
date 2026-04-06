from django.urls import path
from . import views

urlpatterns = [
    path('', views.detect_log),               # → /detect/
    path('nmap/', views.detect_nmap_scan),     # → /detect/nmap/  (GET=stats, POST=scan)
    path('block/', views.manual_block_ip),     # → /detect/block/
    path('unblock/', views.manual_unblock_ip), # → /detect/unblock/
]