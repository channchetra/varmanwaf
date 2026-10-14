import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Eye, EyeSlash } from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { useToast } from '@/components/ui/Toast'
import { authApi } from '@/api/auth'
import { errorMessage } from '@/api/errors'
import { useAuthStore } from '@/stores/authStore'

/** Mirrors the server-side minimum in `validate_password`. */
const MIN_PASSWORD = 8

/**
 * Blocks the console behind a password change until the first sign-in gate
 * clears. Not dismissible by design: the server keeps rejecting writes until
 * the password is changed anyway, so a dismissible dialog would only hide
 * the reason.
 */
export function ForceChangePasswordDialog() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const setUser = useAuthStore((s) => s.setUser)

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const open = user?.must_change_password === true

  const submit = useMutation({
    mutationFn: async () => {
      await authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      })
      return authApi.me()
    },
    meta: { silentToast: true },
    onSuccess: (updated) => {
      setUser(updated)
      void queryClient.invalidateQueries({ queryKey: ['auth'] })
      toast.success(t('pages.settings.passwordChanged'))
    },
    onError: (err) => setError(errorMessage(err)),
  })

  const onSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (submit.isPending) return
    setError(null)
    if (newPassword.length < MIN_PASSWORD) {
      setError(t('auth.passwordTooShort', { min: MIN_PASSWORD }))
      return
    }
    if (newPassword !== confirmPassword) {
      setError(t('pages.settings.passwordMismatch'))
      return
    }
    submit.mutate()
  }

  if (!open) return null

  return (
    // No `title`/`description` props: the Dialog header would render a close
    // button, and this one must not be dismissible.
    <Dialog open onClose={() => undefined}>
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-base font-semibold text-fg-strong">
            {t('pages.account.forceChange.title')}
          </h2>
          <p className="text-[13px] text-fg-subtle">
            {t('pages.account.forceChange.description')}
          </p>
        </div>
        <Input
          type="password"
          label={t('pages.settings.currentPassword')}
          value={currentPassword}
          autoFocus
          autoComplete="current-password"
          onChange={(e) => setCurrentPassword(e.target.value)}
        />
        <Input
          label={t('pages.settings.newPassword')}
          type={showPassword ? 'text' : 'password'}
          value={newPassword}
          autoComplete="new-password"
          hint={t('auth.passwordHint', { min: MIN_PASSWORD })}
          suffixIcon={
            <button
              type="button"
              onClick={() => setShowPassword((s) => !s)}
              aria-label={
                showPassword ? t('auth.hidePassword') : t('auth.showPassword')
              }
              className="transition-colors hover:text-fg"
            >
              {showPassword ? (
                <EyeSlash weight="duotone" />
              ) : (
                <Eye weight="duotone" />
              )}
            </button>
          }
          onChange={(e) => setNewPassword(e.target.value)}
        />
        <Input
          type={showPassword ? 'text' : 'password'}
          label={t('pages.settings.confirmPassword')}
          value={confirmPassword}
          autoComplete="new-password"
          error={
            confirmPassword !== '' && confirmPassword !== newPassword
              ? t('pages.settings.passwordMismatch')
              : undefined
          }
          onChange={(e) => setConfirmPassword(e.target.value)}
        />
        {error && (
          <p role="alert" className="text-[13px] text-fg-danger">
            {error}
          </p>
        )}
        <div className="flex justify-end">
          <Button
            type="submit"
            variant="primary"
            loading={submit.isPending}
            disabled={!currentPassword || !newPassword || !confirmPassword}
          >
            {t('pages.account.forceChange.submit')}
          </Button>
        </div>
      </form>
    </Dialog>
  )
}

export default ForceChangePasswordDialog
