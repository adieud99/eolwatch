import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'


describe('EOLWatch 인증 화면', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => { cleanup(); vi.unstubAllGlobals() })

  it('로그인하지 않은 사용자에게 로그인 폼을 표시한다', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: '인프라 수명주기 관리' })).toBeInTheDocument()
    expect(screen.getByLabelText('아이디')).toBeInTheDocument()
    expect(screen.getByLabelText('비밀번호')).toBeInTheDocument()
  })

  it('로그인 성공 시 토큰을 저장하고 대시보드를 요청한다', async () => {
    fetch.mockImplementation((url) => {
      if (url === '/api/auth/login') {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ access_token: 'token', user: { id: 1, username: 'admin', role: 'ADMIN' } }) })
      }
      const emptyLists = ['/api/assets', '/api/software', '/api/sboms', '/api/customers', '/api/sites', '/api/checks', '/api/vulnerabilities', '/api/notifications', '/api/auth/audit-logs', '/api/auth/users']
      if (emptyLists.includes(url)) return Promise.resolve({ ok: true, status: 200, json: async () => [] })
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ assets: 0, software_products: 0, sbom_documents: 0, components: 0, dependencies: 0, lifecycle_risk: { EXPIRED: 0, CRITICAL: 0, WARN: 0, SAFE: 0, UNKNOWN: 0 }, sbom_quality: { average_score: 0, below_70: 0 }, urgent_items: [] }) })
    })
    render(<App />)
    fireEvent.change(screen.getByLabelText('아이디'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('비밀번호'), { target: { value: 'Eolwatch!2026' } })
    fireEvent.click(screen.getByRole('button', { name: '로그인' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: '통합 현황' })).toBeInTheDocument())
    expect(localStorage.getItem('eolwatch_token')).toBe('token')
  })
})
