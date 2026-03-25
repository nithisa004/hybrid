from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils.timezone import now
from logs.models import Log
from detection.services import detect_anomaly


@api_view(['POST'])
def detect_log(request):
    data = request.data

    # 🔥 Run ML model
    result = detect_anomaly(data)

    # 🔥 Convert prediction → readable values
    name = "Suspicious Activity" if result == 1 else "Normal Traffic"
    severity = "high" if result == 1 else "low"

    # 🔥 Save in DB (matching frontend UI)
    log = Log.objects.create(
        time=now(),
        name=name,
        severity=severity,
        status="open"
    )

    return Response({
        "message": "Detection complete",
        "log": {
            "time": log.time,
            "name": log.name,
            "severity": log.severity,
            "status": log.status
        }
    })