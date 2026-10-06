import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Certificate,
  Copy,
  DownloadSimple,
  FileArrowDown,
  Plus,
  Trash,
  Users,
  Warning,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Textarea } from '@/components/ui/Textarea'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { mtlsApi, mtlsKeys, downloadPem } from '@/api/mtls'
import { sslKeys } from '@/api/ssl'
import { formatDate } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { MtlsCa, MtlsClientCertificate } from '@/api/types'

/** Mirrors `pki::mtls::MAX_CA_DAYS`. */
const MAX_CA_DAYS = 3650
/** Mirrors `pki::mtls::MAX_CLIENT_CERT_DAYS`. */
const MAX_CERT_DAYS = 730
/** Server defaults, pre-filled so the common case is one click. */
const DEFAULT_CA_DAYS = 3650
const DEFAULT_CERT_DAYS = 365

interface CaDraft {
  name: string
  importMode: boolean
  cert_pem: string
  organization: string
  validity_days: number
}

interface IssueDraft {
  ca_id: string
  name: string
  common_name: string
  organization: string
  validity_days: number
}

const emptyCaDraft: CaDraft = {
  name: '',
  importMode: false,
  cert_pem: '',
  organization: '',
  validity_days: DEFAULT_CA_DAYS,
}

const emptyIssueDraft = (caId: string): IssueDraft => ({
  ca_id: caId,
  name: '',
  common_name: '',
  organization: '',
  validity_days: DEFAULT_CERT_DAYS,
})

/** Material returned exactly once, when a CA is added or a cert is issued. */
interface OneTimeMaterial {
  name: string
  certPem: string
  keyPem: string | null
}

/** First 16 hex chars of a SHA-256 fingerprint, with the rest on hover. */
function shortFingerprint(fingerprint: string): string {
  return fingerprint.length > 16 ? `${fingerprint.slice(0, 16)}…` : fingerprint
}

/**
 * Managed mTLS material for one site: the certificate authorities it trusts and
 * the client certificates issued from them.
 *
 * The backend only exposes these routes to writers (`load_site_write`), so the
 * parent renders this section for admins only.
 */
export function MtlsMaterial({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [caDialogOpen, setCaDialogOpen] = useState(false)
  const [caDraft, setCaDraft] = useState<CaDraft>(emptyCaDraft)
  const [pendingCaDelete, setPendingCaDelete] = useState<MtlsCa | null>(null)
  const [issueDialogOpen, setIssueDialogOpen] = useState(false)
  const [issueDraft, setIssueDraft] = useState<IssueDraft>(emptyIssueDraft(''))
  const [pendingRevoke, setPendingRevoke] = useState<MtlsClientCertificate | null>(null)
  const [revokeReason, setRevokeReason] = useState('')
  const [pendingCertDelete, setPendingCertDelete] =
    useState<MtlsClientCertificate | null>(null)
  const [material, setMaterial] = useState<OneTimeMaterial | null>(null)

  const casQuery = useQuery({
    queryKey: mtlsKeys.cas(siteId),
    queryFn: () => mtlsApi.listCas(siteId),
    enabled: Boolean(siteId),
  })

  const certsQuery = useQuery({
    queryKey: mtlsKeys.certificates(siteId),
    queryFn: () => mtlsApi.listCertificates(siteId),
    enabled: Boolean(siteId),
  })

  const cas = useMemo(() => casQuery.data ?? [], [casQuery.data])
  const certs = useMemo(() => certsQuery.data ?? [], [certsQuery.data])
  const signingCas = useMemo(
    () => cas.filter((ca) => ca.is_active && ca.has_private_key),
    [cas],
  )

  // Adding or removing a CA rewrites `site_ssl.mtls_client_ca` (and can turn
  // mTLS off), so the posture card has to re-read its settings.
  const invalidateCas = () => {
    void queryClient.invalidateQueries({ queryKey: mtlsKeys.cas(siteId) })
    void queryClient.invalidateQueries({ queryKey: sslKeys.settings(siteId) })
  }

  const invalidateCerts = () => {
    void queryClient.invalidateQueries({ queryKey: mtlsKeys.certificates(siteId) })
    void queryClient.invalidateQueries({ queryKey: mtlsKeys.cas(siteId) })
  }

  const createCa = useMutation({
    mutationFn: (draft: CaDraft) =>
      mtlsApi.createCa(siteId, {
        name: draft.name.trim(),
        cert_pem: draft.importMode ? draft.cert_pem : undefined,
        organization: draft.organization.trim() || undefined,
        validity_days: draft.importMode ? undefined : draft.validity_days,
      }),
    onSuccess: (created) => {
      toast.success(t('pages.ssl.caCreated'), created.name)
      setCaDialogOpen(false)
      setCaDraft(emptyCaDraft)
      invalidateCas()
      if (created.key_pem) {
        setMaterial({
          name: created.name,
          certPem: created.cert_pem,
          keyPem: created.key_pem,
        })
      }
    },
  })

  const deleteCa = useMutation({
    mutationFn: (ca: MtlsCa) => mtlsApi.deleteCa(siteId, ca.id),
    onSuccess: (_data, ca) => {
      toast.success(t('pages.ssl.caDeleted'), ca.name)
      setPendingCaDelete(null)
      invalidateCas()
      invalidateCerts()
    },
  })

  const issueCertificate = useMutation({
    mutationFn: (draft: IssueDraft) =>
      mtlsApi.issueCertificate(siteId, {
        ca_id: draft.ca_id,
        name: draft.name.trim() || undefined,
        common_name: draft.common_name.trim() || undefined,
        organization: draft.organization.trim() || undefined,
        validity_days: draft.validity_days,
      }),
    onSuccess: (issued) => {
      toast.success(t('pages.ssl.certIssued'), issued.name)
      setIssueDialogOpen(false)
      setIssueDraft(emptyIssueDraft(''))
      invalidateCerts()
      if (issued.key_pem) {
        setMaterial({
          name: issued.name,
          certPem: issued.cert_pem,
          keyPem: issued.key_pem,
        })
      }
    },
  })

  const revokeCertificate = useMutation({
    mutationFn: ({ cert, reason }: { cert: MtlsClientCertificate; reason: string }) =>
      mtlsApi.revokeCertificate(siteId, cert.id, reason),
    onSuccess: (_data, { cert }) => {
      toast.success(t('pages.ssl.certRevoked'), cert.name)
      setPendingRevoke(null)
      setRevokeReason('')
      invalidateCerts()
    },
  })

  const deleteCertificate = useMutation({
    mutationFn: (cert: MtlsClientCertificate) =>
      mtlsApi.deleteCertificate(siteId, cert.id),
    onSuccess: (_data, cert) => {
      toast.success(t('pages.ssl.certDeleted'), cert.name)
      setPendingCertDelete(null)
      invalidateCerts()
    },
  })

  const download = useMutation({
    mutationFn: (cert: MtlsClientCertificate) =>
      mtlsApi.downloadCertificate(siteId, cert.id),
    onSuccess: (pem, cert) => {
      downloadPem(cert.name, pem)
      toast.success(t('pages.ssl.bundleDownloaded'), cert.name)
    },
  })

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success(t('pages.ssl.copied'))
    } catch {
      toast.error(t('pages.ssl.copyFailed'))
    }
  }

  const openIssueDialog = () => {
    setIssueDraft(emptyIssueDraft(signingCas[0]?.id ?? ''))
    setIssueDialogOpen(true)
  }

  const caColumns: Column<MtlsCa>[] = [
    {
      key: 'name',
      header: t('pages.ssl.caName'),
      cell: (ca) => (
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="truncate text-[13px] font-medium text-fg-strong">{ca.name}</p>
            <Badge tone={ca.has_private_key ? 'brand' : 'neutral'} size="sm">
              {ca.has_private_key
                ? t('pages.ssl.caSourceGenerated')
                : t('pages.ssl.caSourceImported')}
            </Badge>
          </div>
          <p
            className="pw-mono truncate text-xs text-fg-subtle"
            title={ca.fingerprint_sha256}
          >
            {shortFingerprint(ca.fingerprint_sha256)}
          </p>
        </div>
      ),
    },
    {
      key: 'organization',
      header: t('pages.ssl.caOrganization'),
      cell: (ca) =>
        ca.expected_organization ?? <span className="text-fg-subtle">—</span>,
    },
    {
      key: 'certificates',
      header: t('pages.ssl.clientCerts'),
      align: 'right',
      cell: (ca) => ca.certificate_count,
    },
    {
      key: 'not_after',
      header: t('pages.ssl.expires'),
      cell: (ca) => formatDate(ca.not_after),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (ca) => (
        <Button
          variant="ghost"
          size="icon"
          aria-label={`${t('common.delete')} ${ca.name}`}
          onClick={() => setPendingCaDelete(ca)}
        >
          <Trash className="h-4 w-4" />
        </Button>
      ),
    },
  ]

  const certColumns: Column<MtlsClientCertificate>[] = [
    {
      key: 'name',
      header: t('pages.ssl.certName'),
      cell: (cert) => (
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="truncate text-[13px] font-medium text-fg-strong">{cert.name}</p>
            <Badge
              tone={cert.status === 'revoked' ? 'danger' : 'success'}
              size="sm"
              dot
            >
              {cert.status === 'revoked'
                ? t('pages.ssl.statusRevoked')
                : t('pages.ssl.statusActive')}
            </Badge>
          </div>
          <p className="pw-mono truncate text-xs text-fg-subtle" title={cert.common_name}>
            {cert.common_name}
          </p>
        </div>
      ),
    },
    {
      key: 'organization',
      header: t('pages.ssl.certOrganization'),
      cell: (cert) =>
        cert.organization ?? <span className="text-fg-subtle">—</span>,
    },
    {
      key: 'ca',
      header: t('pages.ssl.caTitle'),
      cell: (cert) => cert.ca_name ?? '—',
    },
    {
      key: 'not_after',
      header: t('pages.ssl.expires'),
      cell: (cert) => formatDate(cert.not_after),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (cert) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            variant="ghost"
            size="icon"
            aria-label={`${t('pages.ssl.download')} ${cert.name}`}
            loading={download.isPending && download.variables?.id === cert.id}
            onClick={() => download.mutate(cert)}
          >
            <FileArrowDown className="h-4 w-4" />
          </Button>
          {cert.status !== 'revoked' && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setRevokeReason('')
                setPendingRevoke(cert)
              }}
            >
              {t('pages.ssl.revoke')}
            </Button>
          )}
          {cert.status === 'revoked' && (
            <Button
              variant="ghost"
              size="icon"
              aria-label={`${t('common.delete')} ${cert.name}`}
              onClick={() => setPendingCertDelete(cert)}
            >
              <Trash className="h-4 w-4" />
            </Button>
          )}
        </div>
      ),
    },
  ]

  return (
    <>
      {/* Certificate authorities */}
      <Card className="mb-6">
        <CardHeader
          title={t('pages.ssl.caTitle')}
          description={t('pages.ssl.caHint')}
          action={
            <Button
              variant="secondary"
              size="sm"
              icon={<Plus className="h-4 w-4" />}
              onClick={() => {
                setCaDraft(emptyCaDraft)
                setCaDialogOpen(true)
              }}
            >
              {t('pages.ssl.addCa')}
            </Button>
          }
        />
        <CardBody className="p-0">
          {casQuery.isPending ? (
            <SkeletonRows rows={2} columns={4} />
          ) : cas.length === 0 ? (
            <EmptyState
              className="border-0 py-10"
              icon={<Users weight="duotone" className="h-8 w-8" />}
              title={t('pages.ssl.caEmpty')}
              description={t('pages.ssl.caEmptyDescription')}
            />
          ) : (
            <Table
              columns={caColumns}
              data={cas}
              rowKey={(ca) => ca.id}
              dense
              pageSize={0}
            />
          )}
        </CardBody>
      </Card>

      {/* Client certificates */}
      <Card className="mb-6">
        <CardHeader
          title={t('pages.ssl.clientCerts')}
          description={t('pages.ssl.clientCertsHint')}
          action={
            <Button
              variant="secondary"
              size="sm"
              icon={<Certificate className="h-4 w-4" />}
              disabled={signingCas.length === 0}
              title={
                signingCas.length === 0
                  ? t('pages.ssl.issueNeedsGeneratedCa')
                  : undefined
              }
              onClick={openIssueDialog}
            >
              {t('pages.ssl.issueCert')}
            </Button>
          }
        />
        <CardBody className="p-0">
          {certsQuery.isPending ? (
            <SkeletonRows rows={2} columns={4} />
          ) : certs.length === 0 ? (
            <EmptyState
              className="border-0 py-10"
              icon={<Certificate weight="duotone" className="h-8 w-8" />}
              title={t('pages.ssl.emptyClientCerts')}
              description={
                signingCas.length === 0
                  ? t('pages.ssl.issueNeedsGeneratedCa')
                  : t('pages.ssl.emptyClientCertsDescription')
              }
            />
          ) : (
            <Table
              columns={certColumns}
              data={certs}
              rowKey={(cert) => cert.id}
              dense
              pageSize={0}
            />
          )}
        </CardBody>
      </Card>

      {/* Add / import a CA */}
      <Dialog
        open={caDialogOpen}
        onClose={() => setCaDialogOpen(false)}
        size="md"
        title={t('pages.ssl.addCa')}
        description={t('pages.ssl.addCaHint')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setCaDialogOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              disabled={caDraft.name.trim() === ''}
              loading={createCa.isPending}
              onClick={() => createCa.mutate(caDraft)}
            >
              {t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('pages.ssl.caName')}
            value={caDraft.name}
            placeholder="site-ca"
            onChange={(e) => setCaDraft((prev) => ({ ...prev, name: e.target.value }))}
          />
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Select
              label={t('pages.ssl.caSource')}
              value={caDraft.importMode ? 'imported' : 'generated'}
              options={[
                { value: 'generated', label: t('pages.ssl.caSourceGenerated') },
                { value: 'imported', label: t('pages.ssl.caSourceImported') },
              ]}
              onChange={(e) =>
                setCaDraft((prev) => ({
                  ...prev,
                  importMode: e.target.value === 'imported',
                }))
              }
            />
            {!caDraft.importMode && (
              <Input
                type="number"
                label={t('pages.ssl.caValidity')}
                value={caDraft.validity_days}
                min={1}
                max={MAX_CA_DAYS}
                onChange={(e) =>
                  setCaDraft((prev) => ({
                    ...prev,
                    validity_days: Number(e.target.value),
                  }))
                }
              />
            )}
          </div>
          <Input
            label={t('pages.ssl.caOrganization')}
            value={caDraft.organization}
            hint={t('pages.ssl.caOrganizationHint')}
            onChange={(e) =>
              setCaDraft((prev) => ({ ...prev, organization: e.target.value }))
            }
          />
          {caDraft.importMode && (
            <Textarea
              label={t('pages.ssl.caCertPem')}
              mono
              rows={6}
              value={caDraft.cert_pem}
              placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
              hint={t('pages.ssl.caCertPemHint')}
              onChange={(e) =>
                setCaDraft((prev) => ({ ...prev, cert_pem: e.target.value }))
              }
            />
          )}
        </div>
      </Dialog>

      {/* Issue a client certificate */}
      <Dialog
        open={issueDialogOpen}
        onClose={() => setIssueDialogOpen(false)}
        size="md"
        title={t('pages.ssl.issueCert')}
        description={t('pages.ssl.issueCertHint')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setIssueDialogOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              disabled={
                issueDraft.ca_id === '' ||
                (issueDraft.name.trim() === '' && issueDraft.common_name.trim() === '')
              }
              loading={issueCertificate.isPending}
              onClick={() => issueCertificate.mutate(issueDraft)}
            >
              {t('pages.ssl.issueCert')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Select
            label={t('pages.ssl.selectCa')}
            value={issueDraft.ca_id}
            options={signingCas.map((ca) => ({ value: ca.id, label: ca.name }))}
            onChange={(e) =>
              setIssueDraft((prev) => ({ ...prev, ca_id: e.target.value }))
            }
          />
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Input
              label={t('pages.ssl.certName')}
              value={issueDraft.name}
              placeholder="laptop-alice"
              onChange={(e) =>
                setIssueDraft((prev) => ({ ...prev, name: e.target.value }))
              }
            />
            <Input
              label={t('pages.ssl.certCommonName')}
              value={issueDraft.common_name}
              placeholder="alice"
              hint={t('pages.ssl.certCommonNameHint')}
              onChange={(e) =>
                setIssueDraft((prev) => ({ ...prev, common_name: e.target.value }))
              }
            />
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Input
              label={t('pages.ssl.certOrganization')}
              value={issueDraft.organization}
              hint={t('pages.ssl.certOrganizationHint')}
              onChange={(e) =>
                setIssueDraft((prev) => ({ ...prev, organization: e.target.value }))
              }
            />
            <Input
              type="number"
              label={t('pages.ssl.certValidity')}
              value={issueDraft.validity_days}
              min={1}
              max={MAX_CERT_DAYS}
              onChange={(e) =>
                setIssueDraft((prev) => ({
                  ...prev,
                  validity_days: Number(e.target.value),
                }))
              }
            />
          </div>
        </div>
      </Dialog>

      {/* One-time material: the key never comes back from the list endpoints */}
      <Dialog
        open={material !== null}
        onClose={() => setMaterial(null)}
        size="lg"
        title={t('pages.ssl.materialTitle')}
        description={t('pages.ssl.materialHint')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setMaterial(null)}>
              {t('common.close')}
            </Button>
            <Button
              variant="primary"
              icon={<DownloadSimple className="h-4 w-4" />}
              onClick={() => {
                if (!material) return
                const bundle = material.keyPem
                  ? `${material.certPem.trim()}\n${material.keyPem.trim()}\n`
                  : material.certPem
                downloadPem(material.name, bundle)
              }}
            >
              {t('pages.ssl.download')}
            </Button>
          </>
        }
      >
        {material && (
          <div className="flex flex-col gap-4">
            <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[13px] text-fg">
              <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
              {t('pages.ssl.materialOnce')}
            </p>
            <CopyBlock
              label={t('pages.ssl.certPem')}
              value={material.certPem}
              copyLabel={t('pages.ssl.copy')}
              onCopy={copy}
            />
            {material.keyPem && (
              <CopyBlock
                label={t('pages.ssl.privateKey')}
                value={material.keyPem}
                copyLabel={t('pages.ssl.copy')}
                onCopy={copy}
              />
            )}
          </div>
        )}
      </Dialog>

      {/* Revoke */}
      <Dialog
        open={pendingRevoke !== null}
        onClose={() => setPendingRevoke(null)}
        size="md"
        title={t('pages.ssl.revokeTitle')}
        description={t('pages.ssl.revokeDescription')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setPendingRevoke(null)}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="danger"
              loading={revokeCertificate.isPending}
              onClick={() =>
                pendingRevoke &&
                revokeCertificate.mutate({ cert: pendingRevoke, reason: revokeReason })
              }
            >
              {t('pages.ssl.revoke')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          {pendingRevoke && (
            <div className="rounded-md border border-line bg-recessed px-3 py-2">
              <p className="pw-mono text-[13px] font-medium text-fg-strong">
                {pendingRevoke.name}
              </p>
              <p className="pw-mono truncate text-xs text-fg-subtle">
                {pendingRevoke.common_name}
              </p>
            </div>
          )}
          <Input
            label={t('pages.ssl.revokeReason')}
            value={revokeReason}
            placeholder="lost laptop"
            onChange={(e) => setRevokeReason(e.target.value)}
          />
        </div>
      </Dialog>

      <ConfirmDialog
        open={pendingCaDelete !== null}
        onClose={() => setPendingCaDelete(null)}
        onConfirm={() => pendingCaDelete && deleteCa.mutate(pendingCaDelete)}
        title={t('pages.ssl.caDeleteTitle')}
        description={t('pages.ssl.caDeleteDescription')}
        confirmLabel={t('common.delete')}
        loading={deleteCa.isPending}
      >
        {pendingCaDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingCaDelete.name}
            </p>
          </div>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={pendingCertDelete !== null}
        onClose={() => setPendingCertDelete(null)}
        onConfirm={() => pendingCertDelete && deleteCertificate.mutate(pendingCertDelete)}
        title={t('pages.ssl.deleteCertTitle')}
        description={t('pages.ssl.deleteCertDescription')}
        confirmLabel={t('common.delete')}
        loading={deleteCertificate.isPending}
      >
        {pendingCertDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingCertDelete.name}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </>
  )
}

/** Read-only PEM block with a copy button. */
function CopyBlock({
  label,
  value,
  copyLabel,
  onCopy,
}: {
  label: string
  value: string
  copyLabel: string
  onCopy: (value: string) => void
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[13px] font-medium text-fg-subtle">{label}</span>
        <Button
          variant="ghost"
          size="sm"
          icon={<Copy className="h-4 w-4" />}
          onClick={() => onCopy(value)}
        >
          {copyLabel}
        </Button>
      </div>
      <pre
        className={cn(
          'pw-mono max-h-40 overflow-auto rounded-md border border-line bg-recessed',
          'px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap text-fg',
        )}
      >
        {value.trim()}
      </pre>
    </div>
  )
}

export default MtlsMaterial
