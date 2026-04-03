from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),

    path('logs/', include('logs.urls')),         # ✅
    path('detect/', include('detection.urls')),  # ✅
    path('simulate/', include('logs.sim_urls')), # ✅
]