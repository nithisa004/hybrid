from django.db import models


SOURCE_CHOICES = [
    ('windows', 'Windows Event'),
    ('network', 'Network Packet'),
]


class Log(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)

    # Where the event came from
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='windows')

    # Windows Event ID (e.g. 4625, 4688, 4672, 4720) — null for network events
    event_id = models.IntegerField(null=True, blank=True)

    # Human-readable event label (e.g. "Failed Login", "Process Created")
    event_type = models.CharField(max_length=100, blank=True, default='')

    # Autoencoder reconstruction error score
    anomaly_score = models.FloatField(default=0.0)

    # XGBoost output: 0 = normal, 1 = attack
    xgb_prediction = models.IntegerField(default=0)

    # Final decision string (e.g. "CONFIRMED ATTACK", "Normal", "Suspicious Activity")
    result = models.CharField(max_length=100, default='Normal')

    def __str__(self):
        return f"[{self.source}] Event {self.event_id} -> {self.result} @ {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']