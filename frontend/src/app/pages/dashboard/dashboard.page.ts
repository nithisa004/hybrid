import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';
import { ApiService } from '../../services/api.service';
import { addIcons } from 'ionicons';
import { 
  scanOutline, 
  shieldCheckmarkOutline, 
  bugOutline, 
  listOutline,
  checkmarkCircle,
  ellipse,
  checkmark
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

  constructor(private api: ApiService) {
    addIcons({ 
      scanOutline, 
      shieldCheckmarkOutline, 
      bugOutline, 
      listOutline,
      checkmarkCircle,
      ellipse,
      checkmark
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
}