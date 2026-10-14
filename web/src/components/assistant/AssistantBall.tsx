/**
 * Line-art mascot of the AI assistant: a character with centre-parted hair
 * dribbling a basketball. Pure inline SVG in the current-colour line style
 * (matches the phosphor-icon aesthetic and adapts to light/dark themes).
 */
export function AssistantBall({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {/* Shoulders */}
      <path d="M12 42c1.5-6 6-9 12-9s10.5 3 12 9" />
      {/* Head */}
      <circle cx="24" cy="20" r="10.5" />
      {/* Centre-parted hair: two arcs meeting at the crown */}
      <path d="M24 9.5c-4.5.5-8 3.5-9 8.5 2.5-3.5 5.5-5.5 9-5.5" />
      <path d="M24 9.5c4.5.5 8 3.5 9 8.5-2.5-3.5-5.5-5.5-9-5.5" />
      {/* Face */}
      <circle cx="20.5" cy="20.5" r="0.8" fill="currentColor" stroke="none" />
      <circle cx="27.5" cy="20.5" r="0.8" fill="currentColor" stroke="none" />
      <path d="M21.5 24.5c1.5 1.3 3.5 1.3 5 0" />
      {/* Basketball */}
      <circle cx="37" cy="38" r="7" />
      <path d="M37 31v14M30 38h14M32 33.2c2.8 2.6 7.2 2.6 10 0M32 42.8c2.8-2.6 7.2-2.6 10 0" />
    </svg>
  )
}
