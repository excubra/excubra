import { useState, type ReactNode } from "react"
import {
  flexRender, getCoreRowModel, getFilteredRowModel, getPaginationRowModel, getSortedRowModel,
  useReactTable, type ColumnDef, type RowSelectionState, type SortingState, type Row,
} from "@tanstack/react-table"
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { cn } from "@/lib/utils"

// The one table for the console: sortable, searchable, paginated, optional row selection.
// Client-side on purpose — a customer's devices or a fleet of a thousand customers fit
// in memory; the server keeps the queries, the browser keeps the interaction fast.
export function DataTable<T>({
  columns, data, search, searchPlaceholder = "Filtern …", toolbar, pageSize = 25, emptyTitle = "Nichts da", emptyText,
  onRowClick, rowClass, selection, onSelectionChange, footer, initialSort,
}: {
  columns: ColumnDef<T, unknown>[]; data: T[]; search?: (row: T) => string; searchPlaceholder?: string; toolbar?: ReactNode; pageSize?: number
  emptyTitle?: string; emptyText?: ReactNode; onRowClick?: (row: T) => void; rowClass?: (row: T) => string
  selection?: boolean; onSelectionChange?: (rows: T[]) => void; footer?: ReactNode; initialSort?: SortingState
}) {
  const [sorting, setSorting] = useState<SortingState>(initialSort ?? [])
  const [globalFilter, setGlobalFilter] = useState("")
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({})
  const table = useReactTable({
    data, columns, state: { sorting, globalFilter, rowSelection },
    onSortingChange: setSorting, onGlobalFilterChange: setGlobalFilter,
    onRowSelectionChange: (u) => {
      const next = typeof u === "function" ? u(rowSelection) : u
      setRowSelection(next)
      onSelectionChange?.(Object.keys(next).map((i) => data[Number(i)]).filter(Boolean))
    },
    enableRowSelection: !!selection,
    globalFilterFn: (row: Row<T>, _col, value: string) => {
      const hay = search ? search(row.original) : JSON.stringify(row.original)
      return hay.toLowerCase().includes(String(value).toLowerCase())
    },
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(), getFilteredRowModel: getFilteredRowModel(), getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  })
  const rows = table.getRowModel().rows
  const total = table.getFilteredRowModel().rows.length
  return (
    <div className="flex flex-col gap-3">
      {(search || toolbar) && (
        <div className="flex flex-wrap items-center gap-2">
          {search && (
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input value={globalFilter} onChange={(e) => setGlobalFilter(e.target.value)} placeholder={searchPlaceholder} className="h-8 w-64 pl-8" />
            </div>
          )}
          {toolbar}
        </div>
      )}
      <div className="overflow-hidden rounded-md border">
        <Table>
          <TableHeader className="bg-muted sticky top-0 z-10">
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((h) => {
                  const sorted = h.column.getIsSorted()
                  return (
                    <TableHead key={h.id} className={cn(h.column.getCanSort() && "cursor-pointer select-none", (h.column.columnDef.meta as { align?: string } | undefined)?.align === "right" && "text-right")} onClick={h.column.getCanSort() ? h.column.getToggleSortingHandler() : undefined}>
                      <span className="inline-flex items-center gap-1">
                        {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                        {sorted === "asc" && <ArrowUp className="size-3" />}{sorted === "desc" && <ArrowDown className="size-3" />}
                      </span>
                    </TableHead>
                  )
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {rows.length ? rows.map((row) => (
              <TableRow key={row.id} data-state={row.getIsSelected() && "selected"} className={cn(onRowClick && "cursor-pointer", rowClass?.(row.original))} onClick={onRowClick ? (e) => { if ((e.target as HTMLElement).closest("button,a,input,[role=switch],[role=menuitem]")) return; onRowClick(row.original) } : undefined}>
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id} className={cn((cell.column.columnDef.meta as { align?: string } | undefined)?.align === "right" && "text-right tabular-nums")}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
                ))}
              </TableRow>
            )) : (
              <TableRow><TableCell colSpan={columns.length} className="h-40">
                <Empty className="py-6"><EmptyHeader><EmptyTitle>{emptyTitle}</EmptyTitle>{emptyText && <EmptyDescription>{emptyText}</EmptyDescription>}</EmptyHeader></Empty>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
        <span>{selection && table.getFilteredSelectedRowModel().rows.length > 0 ? `${table.getFilteredSelectedRowModel().rows.length} von ${total} ausgewählt` : `${total} Zeile${total === 1 ? "" : "n"}`}</span>
        {footer}
        <div className="ml-auto flex items-center gap-2">
          {total > pageSize && (
            <>
              <span className="hidden sm:inline">Zeilen je Seite</span>
              <Select value={String(table.getState().pagination.pageSize)} onValueChange={(v) => table.setPageSize(Number(v))}>
                <SelectTrigger size="sm" className="w-[70px]"><SelectValue /></SelectTrigger>
                <SelectContent>{[10, 25, 50, 100, 250].map((n) => <SelectItem key={n} value={String(n)}>{n}</SelectItem>)}</SelectContent>
              </Select>
              <span className="tabular-nums">Seite {table.getState().pagination.pageIndex + 1} von {table.getPageCount()}</span>
              <Button variant="outline" size="icon-sm" onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()}><ChevronsLeft /></Button>
              <Button variant="outline" size="icon-sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}><ChevronLeft /></Button>
              <Button variant="outline" size="icon-sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}><ChevronRight /></Button>
              <Button variant="outline" size="icon-sm" onClick={() => table.setPageIndex(table.getPageCount() - 1)} disabled={!table.getCanNextPage()}><ChevronsRight /></Button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
