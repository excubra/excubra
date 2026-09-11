import type { ReactNode } from "react"
import { createPortal } from "react-dom"
import { Link } from "react-router"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"

export type Crumb = { label: string; to?: string }

// Crumbs render into the top bar (a portal), the title block into the page.
export function PageHeader({ crumbs, title, sub, actions, children }: { crumbs: Crumb[]; title: ReactNode; sub?: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  const slot = document.getElementById("crumbs")
  return (
    <>
      {slot && createPortal(
        <Breadcrumb>
          <BreadcrumbList>
            {crumbs.map((c, i) => (
              <span key={i} className="contents">
                {i > 0 && <BreadcrumbSeparator />}
                <BreadcrumbItem>{c.to ? <BreadcrumbLink asChild><Link to={c.to}>{c.label}</Link></BreadcrumbLink> : <BreadcrumbPage>{c.label}</BreadcrumbPage>}</BreadcrumbItem>
              </span>
            ))}
          </BreadcrumbList>
        </Breadcrumb>,
        slot,
      )}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="flex flex-wrap items-center gap-3 text-2xl font-semibold tracking-tight">{title}</h1>
          {sub && <p className="mt-1 text-sm text-muted-foreground">{sub}</p>}
          {children}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </>
  )
}
