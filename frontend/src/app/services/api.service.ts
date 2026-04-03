import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
    providedIn: 'root',
})
export class ApiService {
    private baseUrl = 'http://localhost:8000';

    constructor(private http: HttpClient) { }

    detect(payload: any = {}) {
        return this.http.post(`${this.baseUrl}/detect/`, payload);
    }

    // Pass ?since= to show only current-session logs (starts at 0 on each page load)
    getLogs(since?: string) {
        const url = since
            ? `${this.baseUrl}/logs/?since=${encodeURIComponent(since)}`
            : `${this.baseUrl}/logs/`;
        return this.http.get(url);
    }

    blockThreat(logId: number, adminPassword?: string) {
        return this.http.post(`${this.baseUrl}/logs/block/${logId}/`, { admin_password: adminPassword });
    }

    denyThreat(logId: number, adminPassword?: string) {
        return this.http.post(`${this.baseUrl}/logs/deny/${logId}/`, { admin_password: adminPassword });
    }

    downloadReport() {
        return this.http.get(`${this.baseUrl}/logs/export-report/`, { responseType: 'blob' });
    }
}
