from django.db import models

class Log(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Forensic Identification
    name = models.CharField(max_length=200, default="System Event")
    severity = models.CharField(max_length=20, default="Low") # High, Medium, Low
    status = models.CharField(max_length=50, default="Awaiting action") # Closed, Awaiting action
    verdict = models.CharField(max_length=50, default="None") # True Positive, False Positive
    assignee = models.CharField(max_length=100, default="None")
    
    # Technical Metadata
    source = models.CharField(max_length=50, default='windows')
    event_id = models.IntegerField(null=True, blank=True)
    description = models.TextField(blank=True, default='')
    threat_type = models.CharField(max_length=150, default='Unknown Attack')
    host = models.CharField(max_length=100, default='LPT-HR-001')
    process_name = models.CharField(max_length=100, default='system.exe')
    process_user = models.CharField(max_length=100, default='SYSTEM')
    target_file = models.CharField(max_length=255, default='N/A')
    file_motw = models.URLField(max_length=500, blank=True, null=True)
    file_md5 = models.CharField(max_length=32, default='N/A')

    # ML Results
    anomaly_score = models.FloatField(default=0.0)
    xgb_prediction = models.IntegerField(default=0)
    result = models.CharField(max_length=100, default='Normal')

    # 🔒 FIREWALL BLOCKING FIELDS
    blocked_ip = models.CharField(max_length=45, null=True, blank=True)  # IPv4/IPv6
    blocked_at = models.DateTimeField(null=True, blank=True)
    is_firewall_blocked = models.BooleanField(default=False)
    block_status = models.CharField(
        max_length=20,
        choices=[('pending', 'Pending'), ('applied', 'Applied'), ('failed', 'Failed')],
        default='pending'
    )
    firewall_rule_id = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return f"{self.name} - {self.result} ({self.severity})"

    class Meta:
        ordering = ['-timestamp']