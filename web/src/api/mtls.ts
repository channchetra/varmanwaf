import { apiClient } from './client'
import type {
  CreateMtlsCaRequest,
  IssueMtlsClientCertRequest,
  MtlsCa,
  MtlsCaCreated,
  MtlsClientCertificate,
  MtlsClientCertIssued,
} from './types'

/**
 * Managed mTLS material — `/api/v1/sites/{siteId}/mtls/*`.
 *
 * A site trusts the CAs listed here; client certificates issued from a
 * generated CA are handed to clients and can be revoked. Private keys are
 * returned by the create/issue call and by the bundle download, never by the
 * list endpoints.
 */
export const mtlsApi = {
  listCas: (siteId: string) =>
    apiClient.get<MtlsCa[]>(`/sites/${siteId}/mtls/cas`),

  createCa: (siteId: string, data: CreateMtlsCaRequest) =>
    apiClient.post<MtlsCaCreated>(`/sites/${siteId}/mtls/cas`, data),

  deleteCa: (siteId: string, caId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/mtls/cas/${caId}`),

  listCertificates: (siteId: string) =>
    apiClient.get<MtlsClientCertificate[]>(`/sites/${siteId}/mtls/certificates`),

  issueCertificate: (siteId: string, data: IssueMtlsClientCertRequest) =>
    apiClient.post<MtlsClientCertIssued>(
      `/sites/${siteId}/mtls/certificates`,
      data,
    ),

  revokeCertificate: (siteId: string, certId: string, reason?: string) => {
    const trimmed = reason?.trim()
    return apiClient.post<MtlsClientCertificate>(
      `/sites/${siteId}/mtls/certificates/${certId}/revoke`,
      trimmed ? { reason: trimmed } : {},
    )
  },

  deleteCertificate: (siteId: string, certId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/mtls/certificates/${certId}`),

  /** Certificate plus key (while stored) as one PEM bundle. */
  downloadCertificate: (siteId: string, certId: string) =>
    apiClient.get<string>(
      `/sites/${siteId}/mtls/certificates/${certId}/download`,
    ),
}

export const mtlsKeys = {
  all: ['mtls'] as const,
  cas: (siteId: string) => [...mtlsKeys.all, 'cas', siteId] as const,
  certificates: (siteId: string) =>
    [...mtlsKeys.all, 'certificates', siteId] as const,
}

/** Triggers a client-side download of a PEM bundle. */
export function downloadPem(filename: string, pem: string): void {
  const blob = new Blob([pem], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename.endsWith('.pem') ? filename : `${filename}.pem`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default mtlsApi
