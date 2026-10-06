import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ShieldCheck,
  EnvelopeSimple,
  Fingerprint,
  Lock,
  Eye,
  EyeSlash,
  ArrowRight,
  Globe,
  Lightning,
  ChartLine,
  UserPlus,
  WarningCircle,
} from '@phosphor-icons/react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { useAuthStore } from '@/stores/authStore'
import { useToast } from '@/components/ui/Toast'
import { supportedLanguages } from '@/i18n'
import { authApi } from '@/api/auth'
import { passkeysApi } from '@/api/passkeys'
import { handleApiError, errorMessage } from '@/api/errors'
import { isPasskeyCancellation, passkeysSupported } from '@/lib/webauthn'
import type { LoginResponse } from '@/api/types'

const langLabels: Record<string, string> = { en: 'English', zh: '中文', ja: '日本語' }

/** Minimum accepted by `POST /auth/register`. */
const MIN_PASSWORD = 8

interface LocationState {
  from?: string
}

export function LoginPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const login = useAuthStore((s) => s.login)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const toast = useToast()

  const redirectTo = (location.state as LocationState | null)?.from ?? '/dashboard'

  const [modeState, setModeState] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  // Bootstrap probe: with no accounts yet the console must offer registration
  // instead of a login form nobody can satisfy.
  const { data: status } = useQuery({
    queryKey: ['auth', 'status'],
    queryFn: () => authApi.status(),
    staleTime: 60_000,
    retry: false,
  })

  const needsSetup = status?.needs_setup ?? false
  const registrationOpen = status?.registration_open ?? false
  // With no accounts yet the only possible flow is registration, so pin the
  // form instead of racing an effect against the user's clicks.
  const mode = needsSetup ? 'register' : modeState

  // Already signed in (e.g. back button from a protected route) → skip ahead.
  useEffect(() => {
    if (isAuthenticated) navigate(redirectTo, { replace: true })
  }, [isAuthenticated, navigate, redirectTo])

  const onSuccess = (data: LoginResponse) => {
    login(data.access_token, data.user, data.refresh_token)
    // Drop anything cached under the previous identity.
    queryClient.clear()
    toast.success(t('auth.welcomeBack'), data.user.name ?? data.user.email)
    navigate(redirectTo, { replace: true })
  }

  const signIn = useMutation({
    mutationFn: authApi.login,
    onSuccess,
    meta: { silentToast: true },
    onError: (err) => {
      setFormError(errorMessage(err) || t('auth.invalidCredentials'))
      handleApiError(err, { silent: true })
    },
  })

  const signUp = useMutation({
    mutationFn: authApi.register,
    onSuccess,
    meta: { silentToast: true },
    onError: (err) => {
      setFormError(errorMessage(err))
      handleApiError(err, { silent: true })
    },
  })

  const signInWithPasskey = useMutation({
    mutationFn: () => passkeysApi.login(),
    onSuccess,
    meta: { silentToast: true },
    onError: (err) => {
      // Dismissing the browser's prompt is a normal outcome, not an error.
      if (isPasskeyCancellation(err)) return
      setFormError(errorMessage(err) || t('auth.passkeyFailed'))
      handleApiError(err, { silent: true })
    },
  })

  const showPasskeys =
    mode === 'login' && !needsSetup && (status?.passkey_enabled ?? false) && passkeysSupported()

  const pending = signIn.isPending || signUp.isPending || signInWithPasskey.isPending

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    setFormError(null)

    const trimmedEmail = email.trim()
    if (!trimmedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      setFormError(t('auth.invalidEmail'))
      return
    }
    if (!password) {
      setFormError(t('auth.passwordRequired'))
      return
    }
    if (mode === 'register' && password.length < MIN_PASSWORD) {
      setFormError(t('auth.passwordTooShort', { min: MIN_PASSWORD }))
      return
    }

    if (mode === 'register') {
      signUp.mutate({
        email: trimmedEmail,
        password,
        name: name.trim() || undefined,
      })
    } else {
      signIn.mutate({ email: trimmedEmail, password })
    }
  }

  const canRegister = mode === 'register' || registrationOpen || needsSetup

  return (
    <div className="grid min-h-full w-full grid-cols-1 lg:grid-cols-2">
      {/* Brand panel */}
      <div className="relative hidden overflow-hidden bg-brand lg:flex lg:flex-col lg:justify-between">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.15]"
          style={{
            backgroundImage:
              'radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)',
            backgroundSize: '22px 22px',
          }}
        />
        <div
          className="pointer-events-none absolute -right-24 -top-24 h-96 w-96 rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(255,255,255,0.35), transparent 70%)' }}
        />
        <div className="relative z-10 flex items-center gap-3 p-10 text-white">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/20 backdrop-blur">
            <ShieldCheck weight="fill" className="h-6 w-6" />
          </span>
          <span className="text-xl font-semibold tracking-tight">PingWAF</span>
        </div>

        <div className="relative z-10 px-10 text-white">
          <h2 className="max-w-md text-4xl font-semibold leading-tight tracking-tight">
            {t('app.tagline')}
          </h2>
          <div className="mt-8 grid max-w-md gap-4">
            <Feature icon={<Globe weight="duotone" className="h-5 w-5" />} text={t('auth.featureMultiSite')} />
            <Feature icon={<Lightning weight="duotone" className="h-5 w-5" />} text={t('auth.featureEdge')} />
            <Feature icon={<ChartLine weight="duotone" className="h-5 w-5" />} text={t('auth.featureAnalytics')} />
          </div>
        </div>

        <div className="relative z-10 p-10 text-sm text-white/70">
          © {new Date().getFullYear()} PingWAF
        </div>
      </div>

      {/* Form panel */}
      <div className="flex flex-col justify-center bg-base px-6 py-12 sm:px-12">
        <div className="mx-auto w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand text-white">
              <ShieldCheck weight="fill" className="h-6 w-6" />
            </span>
            <span className="text-lg font-semibold text-fg-strong">PingWAF</span>
          </div>

          <h1 className="text-2xl font-semibold tracking-tight text-fg-strong">
            {mode === 'register' ? t('auth.registerTitle') : t('auth.loginTitle')}
          </h1>
          <p className="mt-1.5 text-sm text-fg-subtle">
            {needsSetup ? t('auth.setupSubtitle') : t('auth.loginSubtitle')}
          </p>

          {needsSetup && (
            <div className="mt-5 flex items-start gap-2.5 rounded-lg border border-brand/30 bg-brand-soft px-3 py-2.5 text-[13px] leading-relaxed text-fg">
              <WarningCircle weight="fill" className="mt-0.5 h-4 w-4 shrink-0 text-brand" />
              <span>{t('auth.setupNotice')}</span>
            </div>
          )}

          <form onSubmit={onSubmit} className="mt-8 flex flex-col gap-4" noValidate>
            {mode === 'register' && (
              <Input
                label={t('auth.displayName')}
                value={name}
                autoComplete="name"
                placeholder={t('auth.displayNamePlaceholder')}
                onChange={(e) => setName(e.target.value)}
              />
            )}

            <Input
              label={t('auth.email')}
              type="email"
              value={email}
              autoComplete="username"
              placeholder="admin@example.com"
              prefixIcon={<EnvelopeSimple weight="duotone" />}
              onChange={(e) => setEmail(e.target.value)}
              required
            />

            <Input
              label={t('auth.password')}
              type={showPassword ? 'text' : 'password'}
              value={password}
              autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
              placeholder="••••••••"
              error={formError ?? undefined}
              hint={mode === 'register' ? t('auth.passwordHint', { min: MIN_PASSWORD }) : undefined}
              prefixIcon={<Lock weight="duotone" />}
              suffixIcon={
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  aria-label={showPassword ? t('auth.hidePassword') : t('auth.showPassword')}
                  className="transition-colors hover:text-fg"
                >
                  {showPassword ? <EyeSlash weight="duotone" /> : <Eye weight="duotone" />}
                </button>
              }
              onChange={(e) => setPassword(e.target.value)}
              required
            />

            <Button
              type="submit"
              variant="primary"
              size="lg"
              fullWidth
              loading={pending}
              icon={
                !pending ? (
                  mode === 'register' ? (
                    <UserPlus weight="bold" className="h-4 w-4" />
                  ) : (
                    <ArrowRight weight="bold" className="h-4 w-4" />
                  )
                ) : undefined
              }
            >
              {mode === 'register' ? t('auth.createAccount') : t('auth.signIn')}
            </Button>
          </form>

          {showPasskeys && (
            <div className="mt-4 flex flex-col gap-4">
              <div className="flex items-center gap-3">
                <span className="h-px flex-1 bg-line" />
                <span className="text-xs uppercase tracking-wide text-fg-subtle">
                  {t('auth.passkeyDivider')}
                </span>
                <span className="h-px flex-1 bg-line" />
              </div>
              <Button
                type="button"
                variant="secondary"
                size="lg"
                fullWidth
                loading={signInWithPasskey.isPending}
                icon={
                  !signInWithPasskey.isPending ? (
                    <Fingerprint weight="bold" className="h-4 w-4" />
                  ) : undefined
                }
                onClick={() => {
                  setFormError(null)
                  signInWithPasskey.mutate()
                }}
              >
                {t('auth.signInWithPasskey')}
              </Button>
            </div>
          )}

          {!needsSetup && canRegister && (
            <div className="mt-5 text-center text-[13px] text-fg-subtle">
              {mode === 'register' ? (
                <>
                  {t('auth.haveAccount')}{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setModeState('login')
                      setFormError(null)
                    }}
                    className="font-medium text-link hover:underline"
                  >
                    {t('auth.signIn')}
                  </button>
                </>
              ) : (
                <>
                  {t('auth.noAccount')}{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setModeState('register')
                      setFormError(null)
                    }}
                    className="font-medium text-link hover:underline"
                  >
                    {t('auth.createAccount')}
                  </button>
                </>
              )}
            </div>
          )}

          <div className="mt-8 flex items-center justify-between border-t border-line pt-6">
            <span className="text-xs text-fg-subtle">{t('user.language')}</span>
            <div className="flex items-center gap-1">
              {supportedLanguages.map((lng) => (
                <button
                  key={lng}
                  type="button"
                  onClick={() => void i18n.changeLanguage(lng)}
                  className={
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors ' +
                    (i18n.language?.startsWith(lng)
                      ? 'bg-brand-soft text-brand'
                      : 'text-fg-subtle hover:bg-recessed hover:text-fg')
                  }
                >
                  {langLabels[lng]}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function Feature({ icon, text }: { icon: ReactNode; text: string }) {
  return (
    <div className="flex items-center gap-3 text-white/90">
      <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/15">
        {icon}
      </span>
      <span className="text-sm font-medium">{text}</span>
    </div>
  )
}
