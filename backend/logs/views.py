from rest_framework.decorators import api_view
from rest_framework.response import Response
from logs.models import Log

@api_view(['GET'])
def get_logs(request):
    logs = Log.objects.all().order_by('-timestamp')

    data = [
        {
            "time": log.timestamp,  # ✅ map correctly
            "name": log.event_type,  # ✅ rename for UI
            "severity": "high" if log.xgb_prediction == 1 else "low",
            "status": "open" if log.result == 1 else "closed",
            "description": log.source,
            "open": False
        }
        for log in logs
    ]

    return Response(data)