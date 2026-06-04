import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface AwsCreds {
  accessKey: string;
  secretKey: string;
  region: string;
  allRegions?: boolean;
}

export interface AzureCreds {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId?: string;
}

const AWS_ENDPOINTS: Record<string, string> = {
  discovery:  '/api/scan',
  compliance: '/api/compliance/scan',
  risk:       '/api/risk/scan',
  cspm:       '/api/cspm/scan',
  maturity:   '/api/maturity/scan',
  wellarch:   '/api/wellarch/scan',
};

const AZURE_ENDPOINTS: Record<string, string> = {
  discovery:  '/api/azure/scan',
  compliance: '/api/azure/compliance/scan',
  risk:       '/api/azure/risk/scan',
  cspm:       '/api/azure/cspm/scan',
  maturity:   '/api/azure/maturity/scan',
  wellarch:   '/api/azure/wellarch/scan',
};

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = 'http://localhost:5000';
  constructor(private http: HttpClient) {}

  // AWS
  scan(endpoint: string, creds: AwsCreds): Observable<any> {
    return this.http.post(`${this.base}${endpoint}`, creds);
  }
  awsScan(module: string, creds: AwsCreds): Observable<any> {
    return this.http.post(`${this.base}${AWS_ENDPOINTS[module]}`, creds);
  }

  // Azure
  azureScan(module: string, creds: AzureCreds): Observable<any> {
    return this.http.post(`${this.base}${AZURE_ENDPOINTS[module]}`, creds);
  }

  health(): Observable<any> {
    return this.http.get(`${this.base}/api/health`);
  }
}
