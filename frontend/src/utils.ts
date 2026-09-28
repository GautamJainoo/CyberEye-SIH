import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { Severity, Status } from './types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function severityClass(s: Severity) {
  switch (s) {
    case 'Critical': return 'badge-critical'
    case 'High':     return 'badge-high'
    case 'Medium':   return 'badge-medium'
    case 'Low':      return 'badge-low'
  }
}

export function statusClass(s: Status) {
  switch (s) {
    case 'Open':        return 'badge-open'
    case 'In Progress': return 'badge-progress'
    case 'Fixed':       return 'badge-fixed'
  }
}

export function severityDot(s: Severity) {
  switch (s) {
    case 'Critical': return 'bg-red-500'
    case 'High':     return 'bg-orange-500'
    case 'Medium':   return 'bg-amber-500'
    case 'Low':      return 'bg-emerald-500'
  }
}
