import { Badge } from "@/components/ui/badge"
import { Ago } from "@/components/clock"
import { taskLabel } from "@/components/task-menu"
import type { BoxNote, BoxTask } from "@/lib/api"
import { fmtDateTime } from "@/lib/format"

export function TaskState({ t }: { t: BoxTask }) {
  if (!t.DoneAt) return <Badge variant="secondary" className="shrink-0">wartet <Ago t={t.IssuedAt} /></Badge>
  if (t.OK) return <Badge variant="outline" className="shrink-0 border-primary/40 text-primary">erledigt</Badge>
  return <Badge variant="outline" className="shrink-0 border-destructive/40 text-destructive">fehlgeschlagen</Badge>
}

// Tasks of one box, newest first: what was asked, by whom, and what the box answered.
export function TaskList({ tasks }: { tasks: BoxTask[] }) {
  if (tasks.length === 0) return <p className="text-sm text-muted-foreground">Noch keine Aufgabe. Über „Aktionen“ oben rechts eine einreihen.</p>
  return (
    <ul className="divide-y">
      {tasks.map((t) => (
        <li key={t.ID} className="flex items-start gap-3 py-2 text-sm">
          <TaskState t={t} />
          <div className="min-w-0 flex-1">
            <div className="font-medium">{taskLabel(t.Kind)} <span className="font-normal text-muted-foreground">· {t.IssuedBy.replace(/^console:/, "") || "System"} · {fmtDateTime(t.IssuedAt)}</span></div>
            {t.Detail && <div className="text-xs text-muted-foreground">{t.Detail}</div>}
            {t.DoneAt && <div className="text-xs text-muted-foreground">gemeldet {fmtDateTime(t.DoneAt)}</div>}
          </div>
        </li>
      ))}
    </ul>
  )
}

// Heartbeat notes: the agent's own words for an operator (rollbacks, refused updates, NetBird).
export function NoteList({ notes }: { notes: BoxNote[] }) {
  if (notes.length === 0) return <p className="text-sm text-muted-foreground">Keine Meldung. Die Box hatte nichts zu beanstanden.</p>
  return (
    <ul className="divide-y">
      {notes.map((n) => (
        <li key={n.ID} className="flex items-start gap-3 py-2 text-sm">
          <span className="shrink-0 font-mono text-xs text-muted-foreground">{fmtDateTime(n.At)}</span>
          <span className="min-w-0 break-words">{n.Text}</span>
        </li>
      ))}
    </ul>
  )
}
