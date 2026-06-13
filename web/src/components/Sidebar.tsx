import { useState } from 'react'
import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { useAuth } from '../auth'
import { roleAtLeast } from '../api'

// ── inline icons (stroke, currentColor) ───────────────────────────────
const I = (p: ReactNode) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" className="h-[18px] w-[18px] shrink-0">
    {p}
  </svg>
)
const icons = {
  overview: I(<><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></>),
  engagements: I(<><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></>),
  detection: I(<><path d="M12 12 7 5" /><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" opacity="0.5" /><circle cx="12" cy="12" r="1.4" /></>),
  redteam: I(<><path d="M13 3l8 8-3 3-8-8z" /><path d="M11 21l-8-8 3-3 8 8z" /><path d="M14.5 14.5 19 19M9.5 9.5 5 5" /></>),
  users: I(<><circle cx="9" cy="8" r="3.2" /><path d="M3.5 20a5.5 5.5 0 0 1 11 0" /><path d="M16 5.2a3.2 3.2 0 0 1 0 5.6" /><path d="M17.5 14.3A5.5 5.5 0 0 1 21 20" /></>),
}

interface NavItem {
  to: string
  label: string
  icon: ReactNode
  end?: boolean
  minRole?: 'operator' | 'admin'
}

const NAV: NavItem[] = [
  { to: '/', label: 'Overview', icon: icons.overview, end: true },
  { to: '/engagements', label: 'Engagements', icon: icons.engagements },
  { to: '/detection', label: 'Detection', icon: icons.detection },
  { to: '/attacks', label: 'Red team', icon: icons.redteam, minRole: 'operator' },
  { to: '/users', label: 'Users', icon: icons.users, minRole: 'admin' },
]

const KEY = 'miraige_nav_collapsed'

export default function Sidebar() {
  const { identity, signOut } = useAuth()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(KEY) === '1')
  const [hovered, setHovered] = useState(false)
  const expanded = !collapsed || hovered // hover temporarily expands a collapsed rail

  // role-gated destinations (Red team → operator, Users → admin) are hidden below their role
  const nav = NAV.filter((n) => !n.minRole || roleAtLeast(identity?.role, n.minRole))

  const toggle = () => {
    const next = !collapsed
    setCollapsed(next)
    setHovered(false)
    localStorage.setItem(KEY, next ? '1' : '0')
  }

  const item = `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${expanded ? '' : 'justify-center'}`

  return (
    // The <aside> only reserves layout width; the panel is fixed so a hover-expand
    // overlays the content instead of pushing it.
    <aside
      className={`shrink-0 transition-[width] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transition-none ${collapsed ? 'w-16' : 'w-60'}`}
      onMouseEnter={() => collapsed && setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div
        className={`fixed inset-y-0 left-0 z-30 flex h-screen flex-col border-r border-line-strong bg-surface transition-[width] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transition-none ${
          expanded ? 'w-60' : 'w-16'
        } ${hovered && collapsed ? 'shadow-[0_18px_60px_-12px_rgba(60,40,12,0.5)]' : ''}`}
      >
        {/* Morphing wordmark: [AI] is the constant anchor; MIR and GE grow in
            from each side as the rail expands, and retract on collapse. */}
        <div className="flex h-14 items-center justify-center px-3">
          <span className="wordmark flex items-center text-base leading-none" title="MIR[AI]GE">
            <span
              className={`overflow-hidden whitespace-nowrap transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transition-none ${
                expanded ? 'max-w-16 opacity-100' : 'max-w-0 -translate-x-1 opacity-0'
              }`}
            >
              MIR
            </span>
            <span className="whitespace-nowrap">
              <span className="text-mirage">[</span>AI<span className="text-mirage">]</span>
            </span>
            <span
              className={`overflow-hidden whitespace-nowrap transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transition-none ${
                expanded ? 'max-w-16 opacity-100' : 'max-w-0 translate-x-1 opacity-0'
              }`}
            >
              GE
            </span>
          </span>
        </div>

        <nav className="flex-1 space-y-1 px-2 py-2">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              title={expanded ? undefined : n.label}
              className={({ isActive }) =>
                `${item} ${isActive ? 'bg-surface-2 font-medium text-ink' : 'text-ink-soft hover:bg-surface-2/60 hover:text-ink'}`
              }
            >
              {({ isActive }) => (
                <>
                  <span className={isActive ? 'text-mirage' : ''}>{n.icon}</span>
                  {expanded && <span className="whitespace-nowrap">{n.label}</span>}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="space-y-1 border-t border-line px-2 py-2">
          <button onClick={signOut} title={expanded ? undefined : 'Sign out'} className={`${item} w-full text-ink-soft hover:bg-surface-2/60 hover:text-ink`}>
            {I(<><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5M21 12H9" /></>)}
            {expanded && <span>Sign out</span>}
          </button>
          <button onClick={toggle} title={collapsed ? 'Pin open' : 'Collapse'} className={`${item} w-full text-ink-soft hover:bg-surface-2/60 hover:text-ink`}>
            <span className={`transition-transform ${collapsed ? 'rotate-180' : ''}`}>{I(<path d="M15 18l-6-6 6-6" />)}</span>
            {expanded && <span>{collapsed ? 'Pin open' : 'Collapse'}</span>}
          </button>
        </div>
      </div>
    </aside>
  )
}
