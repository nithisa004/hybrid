import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule, AlertController, ToastController } from '@ionic/angular';
import { ApiService } from '../../services/api.service';
import { addIcons } from 'ionicons';
import {
  shieldCheckmarkOutline,
  bugOutline,
  listOutline,
  checkmarkCircle,
  ellipse,
  checkmark,
  shieldHalfOutline,
  alertCircleOutline,
  informationCircleOutline,
  pulseOutline,
  wifiOutline,
  pauseOutline,
  playOutline,
  documentTextOutline,
  closeCircleOutline
} from 'ionicons/icons';

@Component({
  standalone: true,
  imports: [CommonModule, IonicModule],
  selector: 'app-dashboard',
  templateUrl: './dashboard.page.html',
  styleUrls: ['./dashboard.page.scss']
})
export class DashboardPage implements OnInit, OnDestroy {

  threatLogs: any[] = [];
  systemEvents: any[] = [];
  isScanning: boolean = false;
  isPaused: boolean = false;
  nmapAlertsCount: number = 0;  // Kali/Nmap realtime hits

  private sessionStart: string = new Date().toISOString();
  private monitoringInterval: any;

  constructor(
    private api: ApiService,
    private alertController: AlertController,
    private toastController: ToastController
  ) {
    addIcons({
      shieldCheckmarkOutline,
      bugOutline,
      listOutline,
      checkmarkCircle,
      ellipse,
      checkmark,
      shieldHalfOutline,
      alertCircleOutline,
      informationCircleOutline,
      pulseOutline,
      wifiOutline,
      pauseOutline,
      playOutline,
      documentTextOutline,
      closeCircleOutline
    });
  }

  ngOnInit() {
    this.startMonitoring();
  }

  ngOnDestroy() {
    this.stopMonitoring();
  }

  startMonitoring() {
    this.stopMonitoring();

    // Initial Load
    this.loadLogs();
    this.runScan();

    // Set 2-second interval for everything
    this.monitoringInterval = setInterval(() => {
      if (!this.isPaused) {
        this.runScan();
        this.runNmapScan();
        this.loadLogs();
      }
    }, 2000);
  }

  stopMonitoring() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
  }

  togglePause() {
    this.isPaused = !this.isPaused;
    if (!this.isPaused) {
      this.showToast('Monitoring Resumed', 'success');
      this.runScan();
      this.loadLogs();
    } else {
      this.showToast('Monitoring Paused', 'warning');
    }
  }

  private runScan() {
    this.isScanning = true;
    this.api.detect({}).subscribe({
      next: () => {
        this.isScanning = false;
      },
      error: () => { this.isScanning = false; }
    });
  }

  /** Poll the Nmap sensor endpoint — runs in parallel with runScan() */
  private runNmapScan() {
    this.api.detectNmap({}).subscribe({
      next: (res: any) => {
        const found = res?.threats_found ?? 0;
        if (found > 0) {
          this.nmapAlertsCount += found;
          this.showToast(
            `🚨 ${found} Nmap/Kali attack(s) detected from ${res.threats[0]?.source}!`,
            'danger'
          );
        }
      },
      error: () => { /* sensor errors are non-fatal */ }
    });
  }

  getKaliThreatsCount(): number {
    return this.nmapAlertsCount;
  }

  loadLogs() {
    this.api.getLogs(this.sessionStart).subscribe({
      next: (res: any) => {
        const allLogs = res.map((newLog: any) => {
          const existingThreat = this.threatLogs.find(t => t.id === newLog.id);
          const existingEvent = this.systemEvents.find(e => e.id === newLog.id);
          const wasOpen = (existingThreat?.open || existingEvent?.open) || false;
          return { ...newLog, open: wasOpen };
        });

        this.threatLogs = allLogs.filter((l: any) => l.severity !== 'Info');
        this.systemEvents = allLogs.filter((l: any) => l.severity === 'Info');
      },
      error: (err) => console.error('Error loading logs:', err)
    });
  }

  getTotalEventsCount() {
    return this.threatLogs.length + this.systemEvents.length;
  }

  getThreatsCount() {
    return this.threatLogs.length;
  }

  toggle(log: any) {
    log.open = !log.open;
  }

  async blockThreat(log: any, event: Event) {
    event.stopPropagation();

    const alert = await this.alertController.create({
      header: '🔐 Admin Verification',
      message: 'Enter the admin password to block this threat.',
      cssClass: 'admin-alert',
      inputs: [{ name: 'password', type: 'password', placeholder: 'Admin Password' }],
      buttons: [
        { text: 'Cancel', role: 'cancel' },
        {
          text: 'Verify & Block',
          handler: (data) => {
            if (data.password) {
              this.executeBlock(log, data.password);
            } else {
              this.showToast('Password is required', 'danger');
            }
          }
        }
      ]
    });

    await alert.present();
  }

  private executeBlock(log: any, adminPassword: string) {
    this.api.blockThreat(log.id, adminPassword).subscribe({
      next: (res: any) => {
        log.status = res.status;
        log.verdict = res.verdict;
        this.showToast(res.message || 'Threat Block', 'success');
      },
      error: () => {
        this.showToast('Authentication failed', 'danger');
      }
    });
  }

  async denyThreat(log: any, event: Event) {
    event.stopPropagation();

    const alert = await this.alertController.create({
      header: '🔐 Admin Verification',
      message: 'Enter the admin password to deny this threat (Mark as False Positive).',
      cssClass: 'admin-alert',
      inputs: [{ name: 'password', type: 'password', placeholder: 'Admin Password' }],
      buttons: [
        { text: 'Cancel', role: 'cancel' },
        {
          text: 'Verify & Deny',
          handler: (data) => {
            if (data.password) {
              this.executeDeny(log, data.password);
            } else {
              this.showToast('Password is required', 'danger');
            }
          }
        }
      ]
    });

    await alert.present();
  }

  private executeDeny(log: any, adminPassword: string) {
    this.api.denyThreat(log.id, adminPassword).subscribe({
      next: (res: any) => {
        log.status = res.status;
        log.verdict = res.verdict;
        this.showToast(res.message || 'Threat Deny', 'success');
      },
      error: () => {
        this.showToast('Authentication failed', 'danger');
      }
    });
  }

  private async showToast(message: string, color: string) {
    const toast = await this.toastController.create({
      message,
      duration: 2000,
      color,
      position: 'bottom'
    });
    toast.present();
  }

  generateReport() {
    this.api.downloadReport().subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Weekly_Security_Report_${new Date().toISOString().split('T')[0]}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        this.showToast('Security report generated successfully', 'success');
      },
      error: () => this.showToast('Failed to generate report', 'danger')
    });
  }
}