from rest_framework.decorators import api_view
from rest_framework.response import Response
from logs.models import Log

@api_view(['GET'])
def get_logs(request):
    logs = Log.objects.all().order_by('-timestamp')

    data = [
        {
            "id": log.id,
            "time": log.timestamp,
            "name": log.name,
            "severity": log.severity,
            "status": log.status,
            "verdict": log.verdict,
            "assignee": log.assignee,
            "description": log.description,
            "host": log.host,
            "process_name": log.process_name,
            "process_user": log.process_user,
            "target_file": log.target_file,
            "file_md5": log.file_md5,
            "anomaly_score": log.anomaly_score,
            "xgb_prediction": log.xgb_prediction,
            "result": log.result,
            "open": False
        }
        for log in logs
    ]

    return Response(data)