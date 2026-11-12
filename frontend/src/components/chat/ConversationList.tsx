import type { Conversation } from '../../messaging/store'

interface ConversationListProps {
  conversations: Conversation[]
  selected: string | null
  onSelect: (peer: string) => void
}

function lastActivity(conversation: Conversation): number {
  const last = conversation.items[conversation.items.length - 1]
  if (last === undefined) {
    return 0
  }
  const parsed = Date.parse(last.createdAt)
  return Number.isFinite(parsed) ? parsed : 0
}

function preview(conversation: Conversation): string {
  const last = conversation.items[conversation.items.length - 1]
  if (last === undefined) {
    return 'No messages yet'
  }
  if (last.kind === 'error') {
    return 'Message unavailable'
  }
  return last.body.length > 0 ? last.body : '(empty message)'
}

export function ConversationList({
  conversations,
  selected,
  onSelect,
}: ConversationListProps) {
  const ordered = [...conversations].sort(
    (left, right) =>
      lastActivity(right) - lastActivity(left) ||
      left.peer.localeCompare(right.peer),
  )

  if (ordered.length === 0) {
    return (
      <p className="px-4 py-6 text-sm leading-6 text-slate-500">
        No conversations yet. Open one by username above, or wait for a
        message.
      </p>
    )
  }

  return (
    <ul aria-label="Conversations" className="space-y-1 px-2">
      {ordered.map((conversation) => {
        const active = conversation.peer === selected
        return (
          <li key={conversation.peer}>
            <button
              type="button"
              onClick={() => onSelect(conversation.peer)}
              aria-pressed={active}
              className={`w-full rounded-lg px-3 py-2 text-left transition ${
                active
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-300 hover:bg-slate-900'
              }`}
            >
              <span className="flex items-center justify-between gap-3">
                <span className="truncate font-medium">
                  {conversation.peer}
                </span>
                {conversation.blocked !== null ? (
                  <span className="shrink-0 text-xs font-medium text-amber-400">
                    Key changed
                  </span>
                ) : null}
              </span>
              <span className="mt-1 block truncate text-xs text-slate-500">
                {preview(conversation)}
              </span>
            </button>
          </li>
        )
      })}
    </ul>
  )
}
