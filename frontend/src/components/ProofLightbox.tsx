'use client'

import { useEffect } from 'react'
import { X } from 'lucide-react'

export default function ProofLightbox({ src, title, method, onClose }: { src: string; title: string; method?: string[]; onClose: () => void }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    document.addEventListener('keydown', h)
    return () => document.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-50 bg-black/80 overflow-auto p-4" onClick={onClose}>
      <div className="max-w-5xl mx-auto card p-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 mb-3">
          <h3 className="font-semibold text-sm">{title}</h3>
          <button onClick={onClose} aria-label="Close"><X className="w-4 h-4" /></button>
        </div>
        {method && method.length > 0 && (
          <div className="mb-3 text-xs">
            <div className="font-semibold uppercase tracking-wide text-slate-500 mb-1">Method used by the tool</div>
            <ol className="list-decimal ml-5 space-y-0.5">{method.map((m, i) => <li key={i}>{m}</li>)}</ol>
          </div>
        )}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={src} alt={`Proof: ${title}`} className="w-full rounded-lg border border-slate-800" />
      </div>
    </div>
  )
}
