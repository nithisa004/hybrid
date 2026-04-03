from django.urls import path
from . import views

urlpatterns = [
    path('', views.get_logs),   # → /logs/
    path('block/<int:log_id>/', views.block_threat),
    path('deny/<int:log_id>/', views.deny_threat),
    path('export-report/', views.export_weekly_pdf, name='export_report'),
]