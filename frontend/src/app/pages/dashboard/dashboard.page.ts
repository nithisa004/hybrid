import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule, AlertController, ToastController } from '@ionic/angular';
import { ApiService } from '../../services/api.service';
import { addIcons } from 'ionicons';
import { 
  scanOutline, 
  shieldCheckmarkOutline, 
  bugOutline, 
  listOutline,
  checkmarkCircle,
  ellipse,
  checkmark,
  shieldHalfOutline,
  alertCircleOutline,
  informationCircleOutline
} from 'ionicons/icons';

@Component({
  standalone: true,
  imports: [CommonModule, IonicModule],
  selector: 'app-dashboard',
  templateUrl: './dashboard.page.html',
  styleUrls: ['./dashboard.page.scss']
})
export class DashboardPage implements OnInit {

  logs: any[] = [];
  isScanning: boolean = false;

  constructor(
    private api: ApiService,
    private alertController: AlertController,
    private toastController: ToastController
  ) {
    addIcons({ 
      scanOutline, 
      shieldCheckmarkOutline, 
      bugOutline, 
      listOutline,
      checkmarkCircle,
      ellipse,
      checkmark,
      shieldHalfOutline,
      alertCircleOutline,
      informationCircleOutline
    });
  }

  ngOnInit() {
    this.loadLogs();
  }

  getThreatsCount() {
    return this.logs.filter(log => log.severity.toLowerCase() === 'high').length;
  }

  loadLogs() {
    this.api.getLogs().subscribe(
      (res: any) => {
        this.logs = res.map((log: any) => ({
          ...log,
          open: false // Ensure open state is initialized
        }));
      },
      (err) => {
        console.error("Error loading logs:", err);
      }
    );
  }

  runDetection() {
    this.isScanning = true;
    this.api.detect({}).subscribe(
      () => {
        this.isScanning = false;
        this.loadLogs();
      },
      (err) => {
        this.isScanning = false;
        console.error("Detection error:", err);
      }
    );
  }

  toggle(log: any) {
    log.open = !log.open;
  }

  async blockThreat(log: any, event: Event) {
    event.stopPropagation(); // Prevent toggling the row

    const alert = await this.alertController.create({
      header: 'Admin Verification',
      message: 'Please enter the admin password to execute this secure action.',
      cssClass: 'admin-alert',
      inputs: [
        {
          name: 'password',
          type: 'password',
          placeholder: 'Admin Password'
        }
      ],
      buttons: [
        {
          text: 'Cancel',
          role: 'cancel'
        },
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
    this.api.blockThreat(log.id, adminPassword).subscribe(
      (res: any) => {
        log.status = res.status;
        log.verdict = res.verdict;
        log.assignee = res.assignee;
        this.showToast('Threat blocked successfully.', 'success');
      },
      (err) => {
        console.error("Error blocking threat:", err);
        this.showToast(err.error?.error || 'Failed to block threat', 'danger');
      }
    );
  }

  async showToast(message: string, color: string) {
    const toast = await this.toastController.create({
      message,
      duration: 3000,
      color,
      position: 'bottom',
      icon: color === 'success' ? 'shield-checkmark-outline' : 'alert-circle-outline'
    });
    toast.present();
  }
}