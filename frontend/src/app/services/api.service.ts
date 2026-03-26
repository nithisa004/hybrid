import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
    providedIn: 'root',
})
export class ApiService {
    private baseUrl = 'http://localhost:8000'; // Django backend

    constructor(private http: HttpClient) { }

    detect(payload: any = {}) {
        return this.http.post(`${this.baseUrl}/detect/`, payload);
    }


    // 🔥 NEW
    getLogs() {
        return this.http.get(`${this.baseUrl}/logs/`);
    }
}
