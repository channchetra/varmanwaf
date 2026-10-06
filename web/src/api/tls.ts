import { apiClient } from './client'
import type {
  GenerateControlPlaneCertificateRequest,
  TlsStatusView,
  UploadControlPlaneCertificateRequest,
} from './types'

/**
 * The control plane's own HTTPS certificate — `/api/v1/system/tls/*`
 * (administrators only).
 *
 * A self-signed pair is generated on first boot; uploading a real certificate
 * replaces it immediately, with no restart, because the listener resolves the
 * served pair through a reloadable resolver. The private key never comes back
 * over the API — only the certificate can be downloaded.
 */
export const tlsApi = {
  getStatus: () => apiClient.get<TlsStatusView>('/system/tls'),

  /** Serves the certificate currently in use, chain included. */
  downloadCertificate: () =>
    apiClient.get<string>('/system/tls/certificate'),

  uploadCertificate: (data: UploadControlPlaneCertificateRequest) =>
    apiClient.put<TlsStatusView>('/system/tls/certificate', data),

  generateSelfSigned: (data: GenerateControlPlaneCertificateRequest) =>
    apiClient.post<TlsStatusView>('/system/tls/certificate/self-signed', data),
}

export const tlsKeys = {
  all: ['tls'] as const,
  status: () => [...tlsKeys.all, 'status'] as const,
}

/** Triggers a client-side download of the served certificate. */
export function downloadCertificateFile(filename: string, pem: string): void {
  const blob = new Blob([pem], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default tlsApi
