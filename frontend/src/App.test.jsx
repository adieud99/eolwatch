import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'

function workPage(findings, url) {
  const params = new URL(url, 'http://localhost').searchParams
  const hasFix = (finding) => Boolean(finding.fixed_version || finding.fixed_versions?.length)
  const isKernel = (finding) => /^linux|^bpftool$/.test(finding.component_name || '')
  const items = findings.filter((finding) => (!params.has('sbom_id') || String(finding.sbom_id) === params.get('sbom_id')) && (!params.has('component_id') || String(finding.component_id) === params.get('component_id')) && (params.get('status') !== 'OPEN' || ['AFFECTED', 'UNDER_INVESTIGATION'].includes(finding.vex_status))
    && (!params.has('fix') || params.get('fix') === 'ALL' || (params.get('fix') === 'FIXED') === hasFix(finding)) && (params.get('kernel') !== 'false' || !isKernel(finding)))
  const limit = Number(params.get('limit') || 25)
  const offset = Number(params.get('offset') || 0)
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset, as_of: '2026-09-15' }
}

function componentPage(findings, url) {
  const params = new URL(url, 'http://localhost').searchParams
  const rows = workPage(findings, url.replace('/components?', '?').replace(/&limit=\d+/, '').replace(/&offset=\d+/, '')).items
  const rank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1 }
  const groups = new Map()
  rows.forEach((finding) => {
    const key = `${finding.component_name}@${finding.component_version}`
    const group = groups.get(key) || { component_id: finding.component_id || groups.size + 1, component_name: finding.component_name, component_version: finding.component_version, sbom_id: finding.sbom_id, asset_tag: finding.asset_tag, asset_name: finding.asset_name, cve_count: 0, link_count: 0, open_count: 0, max_severity: 'UNKNOWN', fixed_versions: [] }
    group.cve_count += 1; group.link_count += 1
    if (finding.fix_check === 'UPDATE_AVAILABLE') group.update_available_count = (group.update_available_count || 0) + 1
    if (finding.fix_check === 'NO_UPDATE_FOUND') group.no_update_count = (group.no_update_count || 0) + 1
    if (['AFFECTED', 'UNDER_INVESTIGATION'].includes(finding.vex_status)) group.open_count += 1
    if ((rank[finding.severity] || 0) > (rank[group.max_severity] || 0)) group.max_severity = finding.severity
    ;(finding.fixed_versions || (finding.fixed_version ? [finding.fixed_version] : [])).forEach((v) => { if (!group.fixed_versions.includes(v)) group.fixed_versions.push(v) })
    groups.set(key, group)
  })
  const items = [...groups.values()]
  const limit = Number(params.get('limit') || 50)
  const offset = Number(params.get('offset') || 0)
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset, as_of: '2026-09-15' }
}

function openHistoryView(name) {
  fireEvent.click(screen.getByRole('button', { name: '검사 기록' }))
  fireEvent.click(screen.getByRole('tab', { name }))
}

describe('EOLWatch 인증 화면', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => { cleanup(); vi.unstubAllGlobals() })

  it('로그인하지 않은 사용자에게 로그인 폼을 표시한다', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: '개발·인프라 취약점 검사' })).toBeInTheDocument()
    expect(screen.getByLabelText('아이디')).toBeInTheDocument()
    expect(screen.getByLabelText('비밀번호')).toBeInTheDocument()
  })

  it('로그인 성공 시 토큰을 저장하고 대시보드를 요청한다', async () => {
    fetch.mockImplementation((url) => {
      if (url === '/api/auth/login') {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ access_token: 'token', user: { id: 1, username: 'admin', role: 'ADMIN' } }) })
      }
      const emptyLists = ['/api/assets', '/api/software', '/api/sboms', '/api/customers', '/api/sites', '/api/checks', '/api/analyses', '/api/analyses/jobs', '/api/analyses/jobs/active', '/api/notifications', '/api/auth/users']
      if (emptyLists.includes(url)) return Promise.resolve({ ok: true, status: 200, json: async () => [] })
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ assets: 0, software_products: 0, sbom_documents: 0, components: 0, dependencies: 0, open_cves: 0, affected_assets: 0, failed_checks_24h: 0, lifecycle_risk: { EXPIRED: 0, CRITICAL: 0, WARN: 0, SAFE: 0, UNKNOWN: 0 }, sbom_quality: { average_score: 0, below_70: 0 }, urgent_items: [] }) })
    })
    render(<App />)
    fireEvent.change(screen.getByLabelText('아이디'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('비밀번호'), { target: { value: 'Eolwatch!2026' } })
    fireEvent.click(screen.getByRole('button', { name: '로그인' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: '개요' })).toBeInTheDocument())
    expect(localStorage.getItem('eolwatch_token')).toBe('token')
  })
})

describe('등록 완료 후 폼 초기화와 목록 갱신', () => {
  afterEach(() => { cleanup(); vi.unstubAllGlobals() })
  it.each([
    { kind: '서버', nav: /인프라 검사/, open: '+ 서버 등록', path: '/api/assets', fields: { '서버 번호': 'VERIFY-ASSET', '서버 이름': '검증 서버', 'SSH 비밀번호': 'pw' }, submit: '저장', message: '서버를 등록했습니다.', row: '검증 서버', closedLabel: '서버 이름' },
  ])('$kind 등록의 비동기 응답 뒤 폼을 초기화하고 새 항목을 표시한다', async (scenario) => {
    localStorage.clear()
    localStorage.setItem('eolwatch_token', 'token')
    localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'operator', role: 'ADMIN' }))
    const data = { '/api/dashboard/summary': { assets: 0, software_products: 0, sbom_documents: 0, components: 0, lifecycle_risk: {}, sbom_quality: { average_score: 0 }, urgent_items: [] }, '/api/customers': [{ id: 1, name: '기존 고객사', customer_code: 'EXISTING' }] }
    let complete
    vi.stubGlobal('fetch', vi.fn(async (url, options) => {
      if (options?.method === 'POST') {
        assertEndpoint(url)
        const payload = JSON.parse(options.body)
        await new Promise((resolve) => { complete = resolve })
        const result = { id: 99, risk_level: 'UNKNOWN', days_left: null, asset_ids: [], software_count: 0, sbom_count: 0, active: true, ...payload }
        data[url] = [...(data[url] || []), result]
        return { ok: true, status: 201, json: async () => result }
      }
      return { ok: true, status: 200, json: async () => data[url] || [] }
    }))
    function assertEndpoint(url) { expect(url).toBe(scenario.path) }
    render(<App />)
    await screen.findByText('검사 대상')
    fireEvent.click(screen.getByRole('button', { name: scenario.nav }))
    if (scenario.open) fireEvent.click(screen.getByRole('button', { name: scenario.open, exact: true }))
    for (const [label, value] of Object.entries(scenario.fields)) fireEvent.change(screen.getByLabelText(label, { exact: true }), { target: { value } })
    if (scenario.select) fireEvent.change(screen.getByLabelText(scenario.select[0], { exact: true }), { target: { value: scenario.select[1] } })
    fireEvent.click(screen.getByRole('button', { name: scenario.submit, exact: true }))
    await waitFor(() => expect(complete).toBeDefined())
    await act(async () => { complete() })
    expect(screen.getByText(scenario.message)).toBeInTheDocument()
    expect(screen.getByText(scenario.row, { exact: true, selector: 'strong' })).toBeInTheDocument()
    if (scenario.resetLabel) expect(screen.getByLabelText(scenario.resetLabel, { exact: true })).toHaveValue('')
    if (scenario.closedLabel) expect(screen.queryByLabelText(scenario.closedLabel, { exact: true })).not.toBeInTheDocument()
    expect(screen.queryByText(/Cannot read properties/)).not.toBeInTheDocument()
  })
})

describe('웹에서 서버 취약점 분석 실행', () => {
  const asset = { id: 7, asset_tag: 'VM-001', name: '실습 서버', asset_type: 'vm', risk_level: 'UNKNOWN', days_left: null, monitored: true, ip_address: '10.0.1.11', ssh_username: 'ubuntu', software_count: 0, sbom_count: 0 }
  const queued = { id: 50, asset_id: 7, asset_tag: 'VM-001', asset_name: '실습 서버', status: 'QUEUED', requested_at: '2026-09-15T06:00:00Z', analysis_run_id: null, sbom_id: null }
  const failed = { ...queued, status: 'FAILED', error_code: 'SSH_FAILED', error_message: '서버에 연결할 수 없습니다.' }
  let data
  let postResponse
  let jobsResponse

  function response(body, status = 200) { return { ok: status < 400, status, json: async () => body } }
  async function openApp(role = 'ADMIN') {
    localStorage.setItem('eolwatch_token', 'token')
    localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'operator', role }))
    let view
    await act(async () => { view = render(<App />) })
    return view
  }
  function openAssets() { fireEvent.click(screen.getByRole('button', { name: /인프라 검사/ })) }
  function openSecurity() { openAssets() }
  function openCveView() { openHistoryView('CVE 결과·조치') }
  async function startAnalysis() {
    openAssets()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'VM-001 취약점 검사' })) })
  }

  beforeEach(() => {
    localStorage.clear(); vi.useFakeTimers()
    data = {
      '/api/dashboard/summary': { assets: 1, software_products: 0, sbom_documents: 0, components: 0, lifecycle_risk: {}, sbom_quality: { average_score: 0 }, urgent_items: [] },
      '/api/assets': [asset],
      '/api/analyses/jobs': [],
    }
    postResponse = null; jobsResponse = null
    vi.stubGlobal('fetch', vi.fn(async (url, options) => {
      if (url === '/api/analyses/jobs' && jobsResponse) return jobsResponse()
      if (options?.method === 'POST') {
        if (postResponse) return postResponse()
        data['/api/analyses/jobs'] = [queued]
        return response(queued, 202)
      }
      if (url.startsWith('/api/vulnerability-work/components?')) return response(componentPage(data.findings || [], url))
      if (url.startsWith('/api/vulnerability-work?')) return response(workPage(data.findings || [], url))
      return response(data[url] ?? [])
    }))
  })
  afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('설정된 서버의 분석을 한 번 요청하고 202 작업의 진행 화면을 표시한다', async () => {
    let resolveRequest
    postResponse = () => new Promise((resolve) => { resolveRequest = resolve })
    await openApp(); openAssets()
    const button = screen.getByRole('button', { name: 'VM-001 취약점 검사' })
    fireEvent.click(button); fireEvent.click(button)
    expect(button).toBeDisabled()
    expect(button).toHaveTextContent('요청 중…')
    expect(screen.getByRole('button', { name: 'SSH 점검' })).toBeInTheDocument()
    const calls = fetch.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(calls).toHaveLength(1)
    expect(calls[0][0]).toBe('/api/analyses/assets/7/jobs')
    expect(JSON.parse(calls[0][1].body)).toEqual({ scan_scope: 'ubuntu-dpkg-installed' })
    expect(calls[0][1].headers.get('Authorization')).toBe('Bearer token')

    await act(async () => { resolveRequest(response(queued, 202)) })
    const table = within(screen.getByRole('table', { name: '서버 검사 작업' }))
    expect(table.getByText('대기')).toBeInTheDocument()
    expect(table.getByText('작업 #50')).toBeInTheDocument()
    openAssets()
    expect(screen.getByRole('button', { name: 'VM-001 취약점 검사' })).toBeDisabled()
  })

  it('상태만 주기적으로 갱신하고 완료된 새 결과를 한 번 읽어 자동으로 표시한다', async () => {
    await openApp(); await startAnalysis()
    data['/api/analyses/jobs'] = [{ ...queued, status: 'SCANNING' }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(within(screen.getByRole('table', { name: '서버 검사 작업' })).getByText('분석')).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)

    data['/api/analyses/jobs'] = [{ ...queued, status: 'SUCCESS', sbom_id: 9, analysis_run_id: 90 }]
    data['/api/sboms'] = [{ id: 9, component_count: 1 }]
    data['/api/analyses'] = [{ id: 90, sbom_id: 9, asset_tag: 'VM-001', asset_name: '실습 서버', imported_at: queued.requested_at, cve_count: 1, component_count: 1, scanner: 'grype', scanner_version: '0.110.0' }]
    data.findings = [{ link_id: 900, sbom_id: 9, cve_id: 'CVE-2026-12345', component_name: 'demo-package', component_version: '1.0', severity: 'HIGH', vex_status: 'AFFECTED' }]
    openAssets()
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('9')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    expect(screen.getByText('CVE-2026-12345')).toBeInTheDocument()
    openAssets()
    expect(screen.getByRole('button', { name: '작업 50 결과 보기' })).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)
    await act(async () => { await vi.advanceTimersByTimeAsync(6000) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)
  })

  it('다른 화면으로 옮긴 뒤 완료된 검사는 안내만 하고 화면을 바꾸지 않는다', async () => {
    await openApp(); await startAnalysis()
    fireEvent.click(screen.getByRole('button', { name: '검사 기록', exact: true }))
    data['/api/analyses/jobs'] = [{ ...queued, status: 'SUCCESS', sbom_id: 9, analysis_run_id: 90 }]
    data['/api/sboms'] = [{ id: 9, component_count: 1 }]
    data['/api/analyses'] = [{ id: 90, sbom_id: 9, asset_tag: 'VM-001', asset_name: '실습 서버', imported_at: queued.requested_at, cve_count: 1, component_count: 1, scanner: 'grype', scanner_version: '0.110.0' }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(screen.getByText('검사 #50이(가) 완료되었습니다. 결과 보기로 확인하세요.')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /검사 기록 · 검사 이력/ })).toBeInTheDocument()
    expect(screen.queryByLabelText('확인할 SBOM')).not.toBeInTheDocument()
  })

  it('실패 원인을 보여주고 재시도를 새 작업으로 추적한다', async () => {
    data['/api/analyses/jobs'] = [failed]
    const retry = { ...queued, id: 51, retry_of_id: 50 }
    postResponse = () => { data['/api/analyses/jobs'] = [retry, failed]; return response(retry, 202) }
    await openApp(); openSecurity()
    expect(screen.getByText('서버에 연결할 수 없습니다.')).toBeInTheDocument()
    expect(screen.getByText('SSH_FAILED')).toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '작업 50 재시도' })) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs/50/retry')).toHaveLength(1)
    expect(fetch.mock.calls.find(([url]) => url === '/api/analyses/jobs/50/retry')[1].body).toBeUndefined()
    expect(screen.getByText('작업 #51 · 작업 #50 재시도')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '작업 50 재시도' })).toBeDisabled()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)
  })

  it('조회자는 작업을 읽을 수 있고 분석·재시도는 할 수 없다', async () => {
    data['/api/analyses/jobs'] = [failed]
    await openApp('VIEWER'); openAssets()
    expect(screen.getByRole('button', { name: 'VM-001 취약점 검사' })).toBeDisabled()
    openSecurity()
    expect(screen.getByRole('button', { name: '작업 50 재시도' })).toBeDisabled()
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs')).toHaveLength(2)
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('SSH 수집 설정이 없는 서버는 분석을 요청할 수 없다', async () => {
    data['/api/assets'] = [{ ...asset, monitored: false }, { ...asset, id: 8, asset_tag: 'VM-002', ip_address: null }, { ...asset, id: 9, asset_tag: 'VM-003', ssh_username: null }]
    await openApp(); openAssets()
    for (const tag of ['VM-001', 'VM-002', 'VM-003']) expect(screen.getByRole('button', { name: `${tag} 취약점 검사` })).toBeDisabled()
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('최근 100건 밖으로 밀린 내가 시작한 작업도 active 목록과 단건 조회로 완료를 추적한다', async () => {
    await openApp(); await startAnalysis()
    const recent = Array.from({ length: 100 }, (_, index) => ({ ...failed, id: index + 200, asset_id: index + 20 }))
    data['/api/analyses/jobs'] = recent
    data['/api/analyses/jobs/active'] = [{ ...queued, status: 'SCANNING' }]
    await act(async () => vi.advanceTimersByTimeAsync(3000))
    expect(within(screen.getByRole('table', { name: '서버 검사 작업' })).getByText('작업 #50')).toBeInTheDocument()
    data['/api/analyses/jobs/active'] = []
    data['/api/analyses/jobs/50'] = { ...queued, status: 'SUCCESS', sbom_id: 9, analysis_run_id: 90 }
    data['/api/sboms'] = [{ id: 9, component_count: 1 }]
    data['/api/analyses'] = [{ id: 90, sbom_id: 9, imported_at: queued.requested_at, asset_id: 7, asset_tag: 'VM-001', scan_scope: 'ubuntu-dpkg-installed', cve_count: 0, component_count: 1 }]
    openAssets()
    await act(async () => vi.advanceTimersByTimeAsync(3000))
    expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('9')
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs/50')).toHaveLength(1)
    expect(fetch.mock.calls.find(([url]) => url === '/api/analyses/jobs/50')[1].headers.get('Authorization')).toBe('Bearer token')
    expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerabilities')).toBe(false)
    await act(async () => vi.advanceTimersByTimeAsync(3000))
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs/50')).toHaveLength(1)
  })

  it('관리자는 작업 취소를 한 번 요청하고 처리 중 상태에서는 재요청할 수 없다', async () => {
    data['/api/analyses/jobs'] = [{ ...queued, status: 'SCANNING' }]
    let complete
    postResponse = () => new Promise((resolve) => { complete = resolve })
    await openApp(); openSecurity()
    const cancel = screen.getByRole('button', { name: '작업 50 취소' })
    fireEvent.click(cancel); fireEvent.click(cancel)
    expect(cancel).toBeDisabled()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs/50/cancel')).toHaveLength(1)
    await act(async () => complete(response({ ...queued, status: 'CANCEL_REQUESTED' })))
    expect(screen.getByRole('button', { name: '작업 50 취소' })).toBeDisabled()
    expect(screen.getByText('실행 중인 프로세스 종료를 확인하고 있습니다.')).toBeInTheDocument()
    data['/api/analyses/jobs'] = [{ ...queued, status: 'CANCELLED' }]
    await act(async () => vi.advanceTimersByTimeAsync(3000))
    expect(screen.getByText('검사를 취소했습니다.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '작업 50 취소' })).not.toBeInTheDocument()
  })

  it('조회자는 대상 상세와 프로젝트 결과로 이동할 수 있고 실행 중 작업을 취소할 수 없다', async () => {
    data['/api/assets/7'] = { ...asset, ssh_port: 2222 }
    data['/api/analyses/jobs'] = [queued]
    data['/api/analyses/projects?asset_id=7&limit=20&offset=0'] = { items: [], total: 0, limit: 20, offset: 0 }
    await openApp('VIEWER'); openAssets()
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'VM-001 서버 상세' })))
    const detail = within(screen.getByRole('region', { name: '서버 정보 관리' }))
    expect(detail.getByText('2222')).toBeInTheDocument()
    expect(detail.queryByRole('button', { name: '서버 변경 저장' })).not.toBeInTheDocument()
    fireEvent.click(detail.getByRole('button', { name: '닫기' }))
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'VM-001 검사 기록' })))
    expect(screen.getByRole('heading', { name: '검사 기록 · 검사 이력' })).toBeInTheDocument()
    expect(screen.getByLabelText('대상')).toHaveValue('7')
    openSecurity()
    expect(screen.queryByRole('button', { name: '작업 50 취소' })).not.toBeInTheDocument()
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('데모 앱 검사 범위를 선택해 서버에 전달하고 작업의 범위를 표시한다', async () => {
    postResponse = () => response({ ...queued, scan_scope: 'demo-python-venv' }, 202)
    await openApp(); openAssets()
    fireEvent.change(screen.getByLabelText('VM-001 검사 범위'), { target: { value: 'demo-python-venv' } })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'VM-001 취약점 검사' })) })
    const call = fetch.mock.calls.find(([url]) => url === '/api/analyses/assets/7/jobs')
    expect(JSON.parse(call[1].body)).toEqual({ scan_scope: 'demo-python-venv' })
    expect(call[1].headers.get('Content-Type')).toBe('application/json')
    expect(within(screen.getByRole('table', { name: '서버 검사 작업' })).getByText('데모 앱 (Python)')).toBeInTheDocument()
  })

  it('느린 상태 조회를 중복 실행하지 않고 요청 이전의 응답으로 새 작업을 덮어쓰지 않는다', async () => {
    let resolveJobs
    jobsResponse = () => new Promise((resolve) => { resolveJobs = resolve })
    await openApp()
    await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs')).toHaveLength(1)
    await startAnalysis()
    await act(async () => { resolveJobs(response([])) })
    expect(within(screen.getByRole('table', { name: '서버 검사 작업' })).getByText('작업 #50')).toBeInTheDocument()
    jobsResponse = null
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs')).toHaveLength(2)
  })

  it('화면 종료 시 진행 중 상태 조회를 취소하고 주기 요청을 중단한다', async () => {
    let resolveJobs
    jobsResponse = () => new Promise((resolve) => { resolveJobs = resolve })
    const view = await openApp()
    const signal = fetch.mock.calls.find(([url]) => url === '/api/analyses/jobs')[1].signal
    view.unmount()
    expect(signal.aborted).toBe(true)
    await act(async () => { resolveJobs(response([queued])); await vi.advanceTimersByTimeAsync(9000) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/jobs')).toHaveLength(1)
  })

  it('분석 요청 오류를 표시하고 다시 요청할 수 있게 한다', async () => {
    postResponse = () => response({ detail: '분석 작업 실행기가 준비되지 않았습니다.' }, 503)
    await openApp(); await startAnalysis()
    expect(screen.getByText('검사 요청 실패: 분석 작업 실행기가 준비되지 않았습니다.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'VM-001 취약점 검사' })).toBeEnabled()
  })

  it('다른 사용자가 실행한 작업의 결과는 결과 보기를 누를 때 불러온다', async () => {
    data['/api/analyses/jobs'] = [queued]
    await openApp('VIEWER'); openCveView()
    data['/api/analyses/jobs'] = [{ ...queued, status: 'SUCCESS', sbom_id: 9, analysis_run_id: 90 }]
    data['/api/sboms'] = [{ id: 9, component_count: 1 }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)
    expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('')
    openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '작업 50 결과 보기' })) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)
    expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('9')
  })

  it('대시보드는 누적 이력과 OS·앱의 마지막 성공 검사을 구분하고 해당 결과로 이동한다', async () => {
    const latest = { asset_id: 7, asset_tag: 'VM-001', asset_name: '실습 서버', scan_scope: 'demo-python-venv', analysis_run_id: 90, sbom_id: 9, cve_count: 0, last_success_at: '2026-09-15T05:00:00Z' }
    data['/api/dashboard/summary'] = { ...data['/api/dashboard/summary'], open_cves: 3219, affected_assets: 1, latest_analyses: [latest, { ...latest, scan_scope: 'ubuntu-dpkg-installed', analysis_run_id: 80, sbom_id: 8, cve_count: 3216 }] }
    data['/api/sboms'] = [{ id: 9, component_count: 3 }, { id: 8, component_count: 670 }]
    await openApp('VIEWER')
    expect(screen.getByText('전체 이력 미조치 CVE')).toBeInTheDocument()
    expect(screen.getByText('전체 검사 이력 기준 · 1대')).toBeInTheDocument()
    const table = within(screen.getByRole('table', { name: '대상 · 범위별 최근 검사' }))
    const appRow = within(table.getByText('데모 앱 (Python)').closest('tr'))
    const osRow = within(table.getByText('OS 설치 패키지').closest('tr'))
    expect(appRow.getByText('0개')).toBeInTheDocument()
    expect(appRow.getByText('검사 당시 미검출')).toBeInTheDocument()
    expect(osRow.getByText('3216개')).toBeInTheDocument()
    await act(async () => { fireEvent.click(appRow.getByRole('button', { name: 'VM-001 데모 앱 (Python) 최근 검사 결과 보기' })) })
    expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('9')
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('대시보드에서 진행·실패 상태를 갱신하면서 이전 성공 시점과 CVE 수를 유지한다', async () => {
    const latest = { asset_id: 7, asset_tag: 'VM-001', asset_name: '실습 서버', scan_scope: 'demo-python-venv', analysis_run_id: 90, sbom_id: 9, cve_count: 0, last_success_at: '2026-09-15T05:00:00Z' }
    data['/api/dashboard/summary'].latest_analyses = [latest]
    await openApp()
    data['/api/analyses/jobs'] = [{ ...queued, scan_scope: 'demo-python-venv', status: 'SCANNING' }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    const table = within(screen.getByRole('table', { name: '대상 · 범위별 최근 검사' }))
    expect(table.getByText('재검사 진행 중입니다. 마지막 성공 검사를 표시합니다.')).toBeInTheDocument()
    data['/api/analyses/jobs'] = [{ ...failed, scan_scope: 'demo-python-venv' }, { ...failed, id: 51, asset_id: 8, asset_tag: 'VM-002', scan_scope: 'ubuntu-dpkg-installed' }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(table.getByText('최근 재검사에 실패했습니다. 마지막 성공 검사를 표시합니다.')).toBeInTheDocument()
    expect(table.getByText('검사 #90 · SBOM #9')).toBeInTheDocument()
    expect(table.getByText('0개')).toBeInTheDocument()
    data['/api/analyses/jobs'] = [{ ...queued, scan_scope: 'demo-python-venv', status: 'CANCELLED' }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(table.getByText('최근 재검사를 취소했습니다. 마지막 성공 검사를 표시합니다.')).toBeInTheDocument()
    expect(table.queryByText('재검사 진행 중입니다. 마지막 성공 검사를 표시합니다.')).not.toBeInTheDocument()
    expect(table.getByText('검사 #90 · SBOM #9')).toBeInTheDocument()
    expect(table.getByText('0개')).toBeInTheDocument()
    data['/api/analyses/jobs'] = [{ ...failed, id: 51, asset_id: 8, asset_tag: 'VM-002', scan_scope: 'ubuntu-dpkg-installed' }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    const firstAttempt = within(table.getByText('VM-002').closest('tr'))
    expect(firstAttempt.getByText('성공한 검사 없음')).toBeInTheDocument()
    expect(firstAttempt.getByText('미확인')).toBeInTheDocument()
    expect(firstAttempt.getByRole('button')).toBeDisabled()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/dashboard/summary')).toHaveLength(1)
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)
  })

  it('다른 사용자의 새 분석 완료를 보면 요약만 한 번 갱신해 대시보드에 반영한다', async () => {
    const latest = { asset_id: 7, asset_tag: 'VM-001', asset_name: '실습 서버', scan_scope: 'demo-python-venv', analysis_run_id: 80, sbom_id: 8, cve_count: 3, last_success_at: '2026-09-15T05:00:00Z' }
    data['/api/dashboard/summary'].latest_analyses = [latest]
    data['/api/analyses/jobs'] = [{ ...queued, scan_scope: 'demo-python-venv' }]
    await openApp('VIEWER')
    data['/api/dashboard/summary'] = { ...data['/api/dashboard/summary'], latest_analyses: [{ ...latest, analysis_run_id: 90, sbom_id: 9, cve_count: 0, last_success_at: '2026-09-15T07:00:00Z' }] }
    data['/api/analyses/jobs'] = [{ ...queued, scan_scope: 'demo-python-venv', status: 'SUCCESS', sbom_id: 9, analysis_run_id: 90 }]
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    const table = within(screen.getByRole('table', { name: '대상 · 범위별 최근 검사' }))
    expect(table.getByText('검사 #90 · SBOM #9')).toBeInTheDocument()
    expect(table.getByText('0개')).toBeInTheDocument()
    await act(async () => { await vi.advanceTimersByTimeAsync(6000) })
    expect(fetch.mock.calls.filter(([url]) => url === '/api/dashboard/summary')).toHaveLength(2)
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities')).toHaveLength(0)
  })

  it('현재 범위의 미조치 수와 전체 이력의 미조치 수를 구분하고 집계가 없으면 미확인으로 표시한다', async () => {
    data['/api/dashboard/summary'] = { ...data['/api/dashboard/summary'], open_cves: 300, affected_assets: 7, current_open_cves: 0, current_affected_assets: 0 }
    const view = await openApp('VIEWER')
    const current = within(screen.getByText('최신 검사 기준 미조치 CVE').closest('article'))
    const historical = within(screen.getByText('전체 이력 미조치 CVE').closest('article'))
    expect(current.getByText('0')).toBeInTheDocument()
    expect(current.getByText('대상·범위별 마지막 검사 기준 · 0대')).toBeInTheDocument()
    expect(historical.getByText('300')).toBeInTheDocument()
    view.unmount(); delete data['/api/dashboard/summary'].current_open_cves
    await openApp('VIEWER')
    expect(within(screen.getByText('최신 검사 기준 미조치 CVE').closest('article')).getByText('미확인')).toBeInTheDocument()
  })
})

describe('SBOM 취약점 분석 흐름', () => {
  const summary = { assets: 1, software_products: 0, sbom_documents: 2, components: 2, dependencies: 0, open_cves: 2, affected_assets: 1, failed_checks_24h: 0, lifecycle_risk: { EXPIRED: 0, CRITICAL: 0, WARN: 0, SAFE: 0, UNKNOWN: 0 }, sbom_quality: { average_score: 100, below_70: 0 }, urgent_items: [] }
  const oldFinding = { link_id: 10, sbom_id: 1, cve_id: 'CVE-2025-11111', component_name: 'old-package', component_version: '1.0', fixed_version: '1.1', severity: 'HIGH', vex_status: 'AFFECTED', asset_tag: 'VM-001', asset_name: '실습 서버', finding_source: 'OSV' }
  const newFinding = { link_id: 20, sbom_id: 2, cve_id: 'CVE-2025-22222', component_name: 'current-package', component_version: '2.0', fixed_version: '2.1', fixed_versions: ['2.1', '3.0'], severity: 'MEDIUM', vex_status: 'AFFECTED', asset_tag: 'VM-001', asset_name: '실습 서버', finding_source: 'Grype', analysis_run_id: 20 }
  const analysis = { id: 20, sbom_id: 2, asset_tag: 'VM-001', asset_name: '실습 서버', scanner: 'grype', scanner_version: '0.110.0', generator: 'syft', scan_scope: '/usr/local/demo', component_count: 1, match_count: 1, cve_count: 1, link_count: 1, ignored_non_cve: 0, imported_at: '2026-09-15T03:00:00Z', database_info: { built: '2026-09-14T00:00:00Z' } }
  let data

  function jsonResponse(body) { return { ok: true, status: 200, json: async () => body } }
  function jsonFile(body) {
    const file = new File([JSON.stringify(body)], 'analysis.json', { type: 'application/json' })
    Object.defineProperty(file, 'text', { value: async () => JSON.stringify(body) })
    return file
  }
  async function openSecurity(role = 'ADMIN') {
    localStorage.setItem('eolwatch_token', 'token')
    localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'operator', role }))
    const view = render(<App />)
    await screen.findByText('검사 대상')
    openHistoryView('CVE 결과·조치')
    await screen.findByRole('heading', { name: '최근 검사 결과' })
    return view
  }

  beforeEach(() => {
    localStorage.clear()
    data = {
      '/api/dashboard/summary': summary,
      '/api/assets': [{ id: 7, asset_tag: 'VM-001', name: '실습 서버' }],
      '/api/sboms': [{ id: 1, component_count: 1 }, { id: 2, component_count: 1 }],
      findings: [oldFinding, newFinding],
      '/api/analyses': [analysis],
      '/api/auth/users': [{ id: 1, username: 'operator', role: 'ADMIN', active: true }, { id: 2, username: 'owner', role: 'VIEWER', active: true }],
    }
    vi.stubGlobal('fetch', vi.fn(async (url, options) => {
      if (url.startsWith('/api/vulnerability-work/components?')) return jsonResponse(componentPage(data.findings, url))
      if (url.startsWith('/api/vulnerability-work?')) return jsonResponse(workPage(data.findings, url))
      if (/^\/api\/vulnerabilities\/\d+$/.test(url) && !options?.method) return jsonResponse({ ...data.findings.find((finding) => finding.link_id === Number(url.split('/').at(-1))), review_revision: 0 })
      if (/\/api\/analyses\/runs\/\d+\/candidates/.test(url)) return jsonResponse({ base: {}, items: [], total: 0, limit: 20, offset: 0 })
      if (/\/api\/vulnerabilities\/\d+\/actions(?:\?.*)?$/.test(url) && !options?.method) return jsonResponse({ items: [], has_more: false, next_before_id: null })
      if (url === '/api/vulnerabilities/20/actions' && options?.method === 'POST') {
        const payload = JSON.parse(options.body)
        const updated = { ...newFinding, vex_status: payload.status, assignee_id: payload.assignee_id, assignee_username: data['/api/auth/users'].find((user) => user.id === payload.assignee_id)?.username, due_date: payload.due_date, detail: payload.detail, review_revision: 1 }
        data.findings = data.findings.map((finding) => finding.link_id === 20 ? updated : finding)
        return jsonResponse(updated)
      }
      if (url === '/api/analyses/import' && options?.method === 'POST') {
        const imported = { ...analysis, id: 30, sbom_id: 3 }
        data['/api/analyses'] = [imported, ...data['/api/analyses']]
        data['/api/sboms'] = [...data['/api/sboms'], { id: 3, component_count: 1 }]
        data.findings = [...data.findings, { ...newFinding, link_id: 30, sbom_id: 3, analysis_run_id: 30 }]
        return jsonResponse(imported)
      }
      return jsonResponse(data[url] ?? [])
    }))
  })

  afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('SBOM 선택에 따라 CVE를 분리하고 전체 수정 버전과 출처를 표시한다', async () => {
    await openSecurity()
    fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' }))
    const findings = within(screen.getByRole('table', { name: '선택한 SBOM의 CVE' }))
    expect(findings.queryByText(oldFinding.cve_id)).not.toBeInTheDocument()
    expect(findings.queryByText(newFinding.cve_id)).not.toBeInTheDocument()

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    expect(findings.getByText(newFinding.cve_id)).toBeInTheDocument()
    expect(findings.queryByText(oldFinding.cve_id)).not.toBeInTheDocument()
    expect(findings.getByText('2.1, 3.0')).toBeInTheDocument()
    expect(findings.getByText('Grype · 검사 #20')).toBeInTheDocument()

    await act(async () => { fireEvent.change(screen.getByLabelText('확인할 SBOM'), { target: { value: '1' } }) })
    expect(findings.getByText(oldFinding.cve_id)).toBeInTheDocument()
    expect(findings.queryByText(newFinding.cve_id)).not.toBeInTheDocument()
    expect(findings.getByText('1.1')).toBeInTheDocument()
    expect(findings.getByText('OSV')).toBeInTheDocument()
  })

  it('조회자는 검사 이력을 읽을 수 있고 업로드·OSV 조회·상태 변경은 할 수 없다', async () => {
    await openSecurity('VIEWER')
    expect(screen.queryByLabelText('검사 결과 JSON 파일')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '검사 결과 저장' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'OSV 조회' })).not.toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    expect(screen.getByText(newFinding.cve_id)).toBeInTheDocument()
    expect(screen.getByLabelText(`${newFinding.cve_id} current-package 조치 상태`)).toHaveTextContent('영향 있음')
    expect(screen.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 이력` })).toBeEnabled()
    expect(within(screen.getByRole('table', { name: '선택한 SBOM의 CVE' })).queryByRole('combobox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '검사 20 원본 보기' })).toBeEnabled()
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('CVE 행은 조치 상태·담당자·기한을 표시하고 바로 상태를 변경하지 않는다', async () => {
    data.findings = [{ ...newFinding, vex_status: 'UNDER_INVESTIGATION', assignee_id: 2, assignee_username: 'owner', due_date: '2026-09-30' }]
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    const row = within(screen.getByRole('table', { name: '선택한 SBOM의 CVE' }))
    expect(row.getByLabelText(`${newFinding.cve_id} current-package 조치 상태`)).toHaveTextContent('조사 중')
    expect(row.getByText('담당 owner')).toBeInTheDocument()
    expect(row.getByText('기한 2026-09-30')).toBeInTheDocument()
    expect(row.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 관리` })).toBeEnabled()
    expect(row.queryByRole('combobox')).not.toBeInTheDocument()
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('조치 패널에서 근거·담당자·기한을 저장한 뒤 패널을 닫고 CVE 목록을 갱신한다', async () => {
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    fireEvent.click(screen.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 관리` }))
    const panel = within(screen.getByRole('region', { name: 'CVE 조치 관리' }))
    await panel.findByText(/아직 기록된 조치 이력이 없습니다/)
    expect(panel.getByRole('button', { name: '조치 내용과 이력 저장' })).toBeDisabled()
    fireEvent.change(panel.getByLabelText('변경할 조치 상태'), { target: { value: 'UNDER_INVESTIGATION' } })
    fireEvent.change(panel.getByLabelText('담당자'), { target: { value: '2' } })
    fireEvent.change(panel.getByLabelText('조치 기한'), { target: { value: '2026-09-30' } })
    fireEvent.change(panel.getByRole('textbox', { name: /^조치 내용/ }), { target: { value: '영향 범위 확인 및 업데이트 일정 검토' } })
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
    fireEvent.click(panel.getByRole('button', { name: '조치 내용과 이력 저장' }))
    await screen.findByText('조치 내용과 이력을 저장했습니다.')
    expect(screen.queryByRole('region', { name: 'CVE 조치 관리' })).not.toBeInTheDocument()
    const post = fetch.mock.calls.find(([url, options]) => url === '/api/vulnerabilities/20/actions' && options.method === 'POST')
    expect(post[1].headers.get('Authorization')).toBe('Bearer token')
    expect(JSON.parse(post[1].body)).toEqual({ expected_revision: 0, status: 'UNDER_INVESTIGATION', detail: '영향 범위 확인 및 업데이트 일정 검토', assignee_id: 2, due_date: '2026-09-30', justification: null, response: null, evidence_analysis_run_id: null })
    expect(fetch.mock.calls.some(([, options]) => options.method === 'PATCH')).toBe(false)
    const findings = within(screen.getByRole('table', { name: '선택한 SBOM의 CVE' }))
    expect(await findings.findByLabelText(`${newFinding.cve_id} current-package 조치 상태`)).toHaveTextContent('조사 중')
    expect(findings.getByText('담당 owner')).toBeInTheDocument()
    expect(findings.getByText('기한 2026-09-30')).toBeInTheDocument()
    expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('2')
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerability-work?sbom_id=2&status=OPEN&fix=ALL&kernel=false&limit=100&offset=0')).toHaveLength(2)
  })

  it('조회자의 조치 이력 패널은 읽기 전용이며 닫을 수 있다', async () => {
    await openSecurity('VIEWER')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    fireEvent.click(screen.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 이력` }))
    const panel = within(screen.getByRole('region', { name: 'CVE 조치 관리' }))
    await panel.findByText(/아직 기록된 조치 이력이 없습니다/)
    expect(panel.getByRole('heading', { name: `${newFinding.cve_id} 조치 이력` })).toBeInTheDocument()
    expect(panel.queryByLabelText('변경할 조치 상태')).not.toBeInTheDocument()
    expect(panel.queryByRole('button', { name: '조치 내용과 이력 저장' })).not.toBeInTheDocument()
    const history = fetch.mock.calls.find(([url]) => url === '/api/vulnerabilities/20/actions?limit=20')
    expect(history[1].headers.get('Authorization')).toBe('Bearer token')
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
    fireEvent.click(panel.getByRole('button', { name: '닫기' }))
    expect(screen.queryByRole('region', { name: 'CVE 조치 관리' })).not.toBeInTheDocument()
    expect(history[1].signal.aborted).toBe(true)
  })

  it('다른 CVE를 선택하면 이전 조치 초안을 새 항목에 넘기지 않는다', async () => {
    data.findings = [newFinding, { ...newFinding, link_id: 21, component_name: 'second-package' }]
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    fireEvent.click(screen.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 관리` }))
    await screen.findByText(/아직 기록된 조치 이력이 없습니다/)
    fireEvent.change(screen.getByRole('textbox', { name: /^조치 내용/ }), { target: { value: '첫 구성요소의 조치 초안' } })
    fireEvent.click(screen.getByRole('button', { name: `${newFinding.cve_id} second-package 조치 관리` }))
    await screen.findByText(/아직 기록된 조치 이력이 없습니다/)
    expect(screen.getByRole('textbox', { name: /^조치 내용/ })).toHaveValue('')
    expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerabilities/21/actions?limit=20')).toBe(true)
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('조치 저장 충돌의 HTTP 상태를 패널로 전달하고 최신 내용을 확인하면서 초안을 유지한다', async () => {
    const defaultFetch = fetch.getMockImplementation()
    let conflicted = false
    fetch.mockImplementation(async (url, options) => {
      if (url === '/api/vulnerabilities/20/actions' && options?.method === 'POST') { conflicted = true; return { ok: false, status: 409, json: async () => ({ detail: '조치 내용이 먼저 변경되었습니다.' }) } }
      if (url === '/api/vulnerabilities/20' && conflicted) return jsonResponse({ ...newFinding, review_revision: 1, vex_status: 'UNDER_INVESTIGATION', detail: '다른 운영자가 영향 범위를 확인했습니다.' })
      return defaultFetch(url, options)
    })
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    fireEvent.click(screen.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 관리` }))
    await screen.findByText(/아직 기록된 조치 이력이 없습니다/)
    const panel = within(screen.getByRole('region', { name: 'CVE 조치 관리' }))
    fireEvent.change(panel.getByRole('textbox', { name: /^조치 내용/ }), { target: { value: '작성 중인 업데이트 계획' } })
    fireEvent.click(panel.getByRole('button', { name: '조치 내용과 이력 저장' }))
    await panel.findByRole('button', { name: '최신 변경을 확인했습니다' })
    expect(panel.getByText('다른 운영자가 영향 범위를 확인했습니다.')).toBeInTheDocument()
    expect(panel.getByRole('textbox', { name: /^조치 내용/ })).toHaveValue('작성 중인 업데이트 계획')
    expect(panel.getByRole('button', { name: '조치 내용과 이력 저장' })).toBeDisabled()
    expect(fetch.mock.calls.find(([url]) => url === '/api/vulnerabilities/20')[1].headers.get('Authorization')).toBe('Bearer token')
  })

  it('CVE 페이지나 SBOM을 바꾸면 조치 패널을 닫고 이력 요청을 취소한다', async () => {
    data.findings = [oldFinding, newFinding, ...Array.from({ length: 100 }, (_, index) => ({ ...newFinding, link_id: 1000 + index, cve_id: `CVE-2026-${20000 + index}` }))]
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    fireEvent.click(screen.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 관리` }))
    await screen.findByText(/아직 기록된 조치 이력이 없습니다/)
    const firstHistory = fetch.mock.calls.find(([url]) => url === '/api/vulnerabilities/20/actions?limit=20')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '다음 페이지' })) })
    expect(screen.queryByRole('region', { name: 'CVE 조치 관리' })).not.toBeInTheDocument()
    expect(firstHistory[1].signal.aborted).toBe(true)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '이전 페이지' })) })
    fireEvent.click(screen.getByRole('button', { name: `${newFinding.cve_id} current-package 조치 관리` }))
    await screen.findByText(/아직 기록된 조치 이력이 없습니다/)
    await act(async () => { fireEvent.change(screen.getByLabelText('확인할 SBOM'), { target: { value: '1' } }) })
    expect(screen.queryByRole('region', { name: 'CVE 조치 관리' })).not.toBeInTheDocument()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities/20/actions?limit=20').every(([, options]) => options.signal.aborted)).toBe(true)
  })

  it('CVE를 100건씩 탐색하고 다른 SBOM을 선택하면 첫 페이지로 돌아간다', async () => {
    data.findings = [oldFinding, ...Array.from({ length: 101 }, (_, index) => ({ ...newFinding, link_id: 1000 + index, cve_id: `CVE-2025-${30000 + index}` }))]
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    const findings = within(screen.getByRole('table', { name: '선택한 SBOM의 CVE' }))
    expect(findings.getAllByRole('row')).toHaveLength(101)
    expect(findings.getByText('CVE-2025-30000')).toBeInTheDocument()
    expect(findings.queryByText('CVE-2025-30100')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '이전 페이지' })).toBeDisabled()

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '다음 페이지' })) })
    expect(findings.getAllByRole('row')).toHaveLength(2)
    expect(findings.getByText('CVE-2025-30100')).toBeInTheDocument()
    expect(findings.queryByText('CVE-2025-30000')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '다음 페이지' })).toBeDisabled()
    expect(screen.getByText('총 101건 · 101–101건 표시')).toBeInTheDocument()
    const pageRequest = fetch.mock.calls.find(([url]) => url === '/api/vulnerability-work?sbom_id=2&status=OPEN&fix=ALL&kernel=false&limit=100&offset=100')
    expect(pageRequest[1].headers.get('Authorization')).toBe('Bearer token')
    expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerabilities')).toBe(false)

    await act(async () => { fireEvent.change(screen.getByLabelText('확인할 SBOM'), { target: { value: '1' } }) })
    expect(findings.getByText(oldFinding.cve_id)).toBeInTheDocument()
    expect(screen.getByText('1 / 1 페이지')).toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    expect(findings.getByText('CVE-2025-30000')).toBeInTheDocument()
    expect(screen.getByText('1 / 2 페이지')).toBeInTheDocument()
  })

  it('SBOM을 선택하기 전에는 CVE를 가져오지 않고 선택을 바꾸면 느린 이전 응답을 폐기한다', async () => {
    const defaultFetch = fetch.getMockImplementation()
    let resolveOld
    fetch.mockImplementation((url, options) => url.includes('/vulnerability-work?sbom_id=2') ? new Promise((resolve) => { resolveOld = resolve }) : defaultFetch(url, options))
    await openSecurity()
    expect(fetch.mock.calls.some(([url]) => url.startsWith('/api/vulnerability-work'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' }))
    fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' }))
    const oldRequest = fetch.mock.calls.find(([url]) => url.includes('/vulnerability-work?sbom_id=2'))
    expect(screen.getByText('CVE 결과를 불러오는 중…')).toBeInTheDocument()
    expect(screen.queryByText('이 SBOM에 저장된 CVE 결과가 없습니다.')).not.toBeInTheDocument()
    await act(async () => { fireEvent.change(screen.getByLabelText('확인할 SBOM'), { target: { value: '1' } }) })
    expect(oldRequest[1].signal.aborted).toBe(true)
    expect(screen.getByText(oldFinding.cve_id)).toBeInTheDocument()
    await act(async () => { resolveOld(jsonResponse(workPage([newFinding], oldRequest[0]))) })
    expect(screen.queryByText(newFinding.cve_id)).not.toBeInTheDocument()
    expect(screen.getByText(oldFinding.cve_id)).toBeInTheDocument()
  })

  it('CVE 페이지 조회 실패를 빈 결과와 구별하고 다시 시도하며 화면 종료 시 조회를 취소한다', async () => {
    const defaultFetch = fetch.getMockImplementation()
    let attempts = 0
    fetch.mockImplementation((url, options) => {
      if (url.startsWith('/api/vulnerability-work?') && ++attempts === 1) return Promise.resolve({ ok: false, status: 503, json: async () => ({ detail: '잠시 후 다시 요청하세요.' }) })
      return defaultFetch(url, options)
    })
    const view = await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    expect(screen.getByRole('alert')).toHaveTextContent('CVE 결과 조회 실패: 잠시 후 다시 요청하세요.')
    expect(screen.queryByText('이 SBOM에 저장된 CVE 결과가 없습니다.')).not.toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE 조회 다시 시도' })) })
    expect(screen.getByText(newFinding.cve_id)).toBeInTheDocument()
    let resolvePending
    fetch.mockImplementation((url, options) => url.includes('/vulnerability-work?sbom_id=1') ? new Promise((resolve) => { resolvePending = resolve }) : defaultFetch(url, options))
    fireEvent.change(screen.getByLabelText('확인할 SBOM'), { target: { value: '1' } })
    const pendingRequest = fetch.mock.calls.find(([url]) => url.includes('/vulnerability-work?sbom_id=1'))
    view.unmount()
    expect(pendingRequest[1].signal.aborted).toBe(true)
    await act(async () => { resolvePending(jsonResponse(workPage([oldFinding], pendingRequest[0]))) })
  })

  it('OSV 완료 후 현재 서버 페이지를 다시 읽고 결과가 줄어들면 유효한 마지막 페이지로 돌아간다', async () => {
    data.findings = [oldFinding, ...Array.from({ length: 101 }, (_, index) => ({ ...newFinding, link_id: 1000 + index, cve_id: `CVE-2026-${30000 + index}` }))]
    const defaultFetch = fetch.getMockImplementation()
    let finishScan
    fetch.mockImplementation((url, options) => url === '/api/vulnerabilities/scan/sbom/2' ? new Promise((resolve) => { finishScan = resolve }) : defaultFetch(url, options))
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '다음 페이지' })) })
    expect(screen.getByText('2 / 2 페이지')).toBeInTheDocument()
    const scanButton = screen.getByRole('button', { name: 'OSV 조회' })
    fireEvent.click(scanButton); fireEvent.click(scanButton)
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerabilities/scan/sbom/2')).toHaveLength(1)
    data.findings = [oldFinding, { ...newFinding, finding_source: 'OSV' }]
    await act(async () => { finishScan(jsonResponse({ unique_vulnerabilities: 1, ignored_non_cve: 0 })) })
    expect(screen.getByText('1 / 1 페이지')).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: '선택한 SBOM의 CVE' })).getByText(newFinding.cve_id)).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerability-work?sbom_id=2&status=OPEN&fix=ALL&kernel=false&limit=100&offset=100')).toHaveLength(2)
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerability-work?sbom_id=2&status=OPEN&fix=ALL&kernel=false&limit=100&offset=0')).toHaveLength(2)
    expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerabilities')).toBe(false)
  })

  it('다른 SBOM으로 이동하면 진행 중 OSV 응답을 취소하고 새 선택에 적용하지 않는다', async () => {
    const defaultFetch = fetch.getMockImplementation()
    let finishScan
    fetch.mockImplementation((url, options) => url === '/api/vulnerabilities/scan/sbom/2' ? new Promise((resolve) => { finishScan = resolve }) : defaultFetch(url, options))
    await openSecurity()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 20 CVE 보기' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    fireEvent.click(screen.getByRole('button', { name: 'OSV 조회' }))
    const scanRequest = fetch.mock.calls.find(([url]) => url === '/api/vulnerabilities/scan/sbom/2')
    await act(async () => { fireEvent.change(screen.getByLabelText('확인할 SBOM'), { target: { value: '1' } }) })
    expect(scanRequest[1].signal.aborted).toBe(true)
    await act(async () => { finishScan(jsonResponse({ unique_vulnerabilities: 99, ignored_non_cve: 0 })) })
    expect(screen.queryByText(/OSV 조회 완료/)).not.toBeInTheDocument()
    expect(screen.getByText(oldFinding.cve_id)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'OSV 조회' })).toBeEnabled()
    expect(fetch.mock.calls.filter(([url]) => url.includes('/vulnerability-work?sbom_id=1'))).toHaveLength(1)
  })

  it('조치 목록에서 전체 미완료 이력을 읽고 저장 후 작업과 요약을 갱신한다', async () => {
    await openSecurity()
    openHistoryView('조치 목록')
    const region = within(await screen.findByRole('region', { name: 'CVE 조치 목록' }))
    await region.findByText(newFinding.cve_id)
    expect(region.getByText(oldFinding.cve_id)).toBeInTheDocument()
    const row = within(region.getByText(newFinding.cve_id).closest('tr'))
    fireEvent.click(row.getByRole('button', { name: '조치 관리' }))
    const panel = within(screen.getByRole('region', { name: 'CVE 조치 관리' }))
    await panel.findByText(/아직 기록된 조치 이력이 없습니다/)
    fireEvent.change(panel.getByLabelText('변경할 조치 상태'), { target: { value: 'FIXED' } })
    fireEvent.change(panel.getByRole('textbox', { name: /^조치 내용/ }), { target: { value: '패치 배포와 정상 동작을 확인했습니다.' } })
    fireEvent.click(panel.getByRole('button', { name: '조치 내용과 이력 저장' }))
    await waitFor(() => expect(region.queryByText(newFinding.cve_id)).not.toBeInTheDocument())
    expect(region.getByText(oldFinding.cve_id)).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([url]) => url === '/api/vulnerability-work?status=OPEN&limit=25&offset=0')).toHaveLength(2)
    expect(fetch.mock.calls.filter(([url]) => url === '/api/dashboard/summary')).toHaveLength(2)
    expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerabilities')).toBe(false)
  })

  it('조회자는 작업목록에서 조치 이력을 읽고 선택한 SBOM의 전체 상태 결과로 이동한다', async () => {
    await openSecurity('VIEWER')
    openHistoryView('조치 목록')
    const region = within(await screen.findByRole('region', { name: 'CVE 조치 목록' }))
    await region.findByText(newFinding.cve_id)
    expect(region.queryByRole('button', { name: '조치 관리' })).not.toBeInTheDocument()
    expect(region.getAllByRole('button', { name: '조치 이력' })).toHaveLength(2)
    await act(async () => { fireEvent.click(region.getByRole('button', { name: 'SBOM #2 결과' })) })
    expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('2')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    expect(screen.getByText(newFinding.cve_id)).toBeInTheDocument()
    expect(screen.queryByText(oldFinding.cve_id)).not.toBeInTheDocument()
    const pageRequest = fetch.mock.calls.find(([url]) => url === '/api/vulnerability-work?sbom_id=2&status=OPEN&fix=ALL&kernel=false&limit=100&offset=0')
    expect(pageRequest[1].headers.get('Authorization')).toBe('Bearer token')
    expect(fetch.mock.calls.some(([url]) => url === '/api/auth/users')).toBe(false)
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

})

describe('구성요소별 CVE 보기', () => {
  afterEach(() => { cleanup(); vi.unstubAllGlobals() })
  it('같은 구성요소의 CVE를 한 줄로 접어 두고 펼치면 그 아래에 나열한다', async () => {
    const mk = (id, cve, name, version, severity, fixed) => ({ link_id: id, sbom_id: 2, component_id: name === 'linux-image' ? 1 : 2, cve_id: cve, component_name: name, component_version: version, fixed_version: fixed, fix_check: fixed ? (name === 'openssl' ? 'UPDATE_AVAILABLE' : 'NO_UPDATE_FOUND') : null, severity, vex_status: 'AFFECTED', asset_tag: 'srv-han', asset_name: '성민 서버', finding_source: 'Grype', analysis_run_id: 20 })
    const findings = [mk(1, 'CVE-2026-1', 'linux-image', '7.0.0-1006', 'HIGH', '7.0.0-1012'), mk(2, 'CVE-2026-2', 'linux-image', '7.0.0-1006', 'MEDIUM', null), mk(3, 'CVE-2026-3', 'linux-image', '7.0.0-1006', 'LOW', '7.0.0-1012'), mk(4, 'CVE-2026-9', 'openssl', '3.5.5', 'CRITICAL', '3.5.5-1ubuntu3.5')]
    const data = { '/api/dashboard/summary': { assets: 1, lifecycle_risk: {}, sbom_quality: {}, urgent_items: [] }, '/api/sboms': [{ id: 2, component_count: 2 }], '/api/analyses': [{ id: 20, sbom_id: 2, asset_tag: 'srv-han', asset_name: '성민 서버', scanner: 'grype', scanner_version: '0.118.0', generator: 'syft', scan_scope: 'ubuntu-dpkg-installed', component_count: 2, match_count: 4, cve_count: 4, link_count: 4, ignored_non_cve: 0, fixable_cve_count: 3, kernel_cve_count: 3, kernel_fixable_cve_count: 2, verified_fixable_cve_count: 1, suspect_cve_count: 2, package_updates: { manager: 'apt', refreshed: true, package_count: 173 }, imported_at: '2026-09-21T09:00:00Z', database_info: {} }] }
    localStorage.clear(); localStorage.setItem('eolwatch_token', 'token'); localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'operator', role: 'ADMIN' }))
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (url.startsWith('/api/vulnerability-work/components?')) return { ok: true, status: 200, json: async () => componentPage(findings, url) }
      if (url.startsWith('/api/vulnerability-work?')) return { ok: true, status: 200, json: async () => workPage(findings, url) }
      return { ok: true, status: 200, json: async () => (url in data ? data[url] : (url.startsWith('/api/ai/') ? null : [])) }
    }))
    render(<App />)
    await screen.findByText('검사 대상')
    openHistoryView('CVE 결과·조치')
    await act(async () => { fireEvent.click(await screen.findByRole('button', { name: '검사 20 CVE 보기' })) })
    // default: kernel packages are folded away and the filter says so
    let table = within(screen.getByRole('table', { name: '구성요소별 CVE' }))
    expect(table.getByText('openssl')).toBeInTheDocument()
    expect(table.queryByText('linux-image')).not.toBeInTheDocument()
    expect(screen.getByText('구성요소 1개 · 1–1개 표시')).toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByLabelText('커널(linux) CVE 포함')) })
    table = within(screen.getByRole('table', { name: '구성요소별 CVE' }))
    expect(table.getByText('linux-image')).toBeInTheDocument()
    expect(table.getByText('3개')).toBeInTheDocument()
    expect(table.getByText('7.0.0-1012')).toBeInTheDocument()
    expect(table.queryByText('CVE-2026-2')).not.toBeInTheDocument()
    await act(async () => { fireEvent.click(table.getByRole('button', { name: 'linux-image CVE 3개 보기' })) })
    const nested = within(await screen.findByRole('table', { name: 'linux-image CVE 목록' }))
    expect(nested.getAllByRole('row')).toHaveLength(4)
    expect(nested.getByText('CVE-2026-2')).toBeInTheDocument()
    expect(nested.getAllByText('저장소에 업데이트 없음 · 오탐 의심')).toHaveLength(2)
    expect(table.getByText('저장소에 업데이트 없음 · 오탐 의심 2건')).toBeInTheDocument()
    expect(table.getByText('저장소에 업데이트 있음 1건')).toBeInTheDocument()
    expect(screen.getByText(/apt 대조: 저장소에 업데이트 있음 1개 · 오탐 의심 2개/)).toBeInTheDocument()
    expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerability-work?sbom_id=2&component_id=1&status=OPEN&fix=ALL&kernel=true&limit=100&offset=0')).toBe(true)
    await act(async () => { fireEvent.click(table.getByRole('button', { name: 'linux-image CVE 3개 접기' })) })
    expect(screen.queryByRole('table', { name: 'linux-image CVE 목록' })).not.toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'CVE별로 보기' })) })
    expect(within(screen.getByRole('table', { name: '선택한 SBOM의 CVE' })).getAllByRole('row')).toHaveLength(5)
  })
})

describe('프로젝트와 대상의 결과 문맥 연결', () => {
  const asset = { id: 7, asset_tag: 'VM-001', name: '주문 서버', asset_type: 'vm', risk_level: 'UNKNOWN', days_left: null, monitored: false }
  const base = { id: 1, asset_id: 7, asset_tag: 'VM-001', asset_name: '주문 서버', scan_scope: 'source-zip:orders', sbom_id: 101, imported_at: '2026-01-01T00:00:00Z', cve_count: 3, component_count: 4, scanner: 'Grype' }
  const target = { ...base, id: 205, sbom_id: 305, imported_at: '2026-09-15T00:00:00Z', cve_count: 0 }
  const project = { asset_id: 7, asset_tag: 'VM-001', asset_name: '주문 서버', scan_scope: base.scan_scope, project_name: 'orders', latest_analysis: target, latest_job: null, schedule: null, analysis_count: 205, job_count: 205, upload_count: 2 }
  const response = (value) => ({ ok: true, status: 200, json: async () => value })
  let runRequest
  async function openProject() {
    render(<App />)
    await screen.findByText('검사 대상')
    openHistoryView('검사 이력')
    fireEvent.click(await screen.findByRole('button', { name: 'VM-001 소스 ZIP · orders 이력 보기' }))
    await screen.findByText('검사 #1', { selector: 'strong' })
  }
  function selectPair() {
    fireEvent.click(within(screen.getByText('검사 #1', { selector: 'strong' }).closest('tr')).getByRole('button', { name: '이전으로' }))
    fireEvent.click(within(screen.getByText('검사 #205', { selector: 'strong' }).closest('tr')).getByRole('button', { name: '이후로' }))
  }
  beforeEach(() => {
    localStorage.clear(); localStorage.setItem('eolwatch_token', 'token'); localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'viewer', role: 'VIEWER' }))
    runRequest = null
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (url === '/api/dashboard/summary') return response({ assets: 1, software_products: 0, sbom_documents: 2, components: 8, lifecycle_risk: {}, sbom_quality: { average_score: 100 }, urgent_items: [] })
      if (url === '/api/assets') return response([asset])
      if (url === '/api/sboms') return response([base, target].map((run) => ({ id: run.sbom_id, serial_number: `urn:sbom:${run.sbom_id}`, component_count: 4, dependency_count: 0, quality_score: 100, quality_details: { checks: {} } })))
      if (url.startsWith('/api/analyses/projects?')) return response({ items: [project], total: 1, limit: 20, offset: 0 })
      if (url.startsWith('/api/analyses/history?')) return response({ items: [target, base], total: 205, limit: 20, offset: 0 })
      if (url.startsWith('/api/analyses/runs/')) return runRequest ? runRequest(url) : response(url.endsWith('/1') ? base : target)
      if (url === '/api/analyses/1/compare/205') return response({ base, target, comparable: true, warnings: [], findings: [], summary: { persistent: 0, new: 0, no_longer_detected: 3, component_removed: 0 } })
      if (url.startsWith('/api/vulnerability-work?')) return response({ items: [], total: 0, limit: 25, offset: 0, as_of: '2026-09-16' })
      if (url === '/api/sboms/101/detail') return response({ id: 101, asset, serial_number: 'urn:sbom:101', component_count: 4, dependency_count: 0, quality_score: 100 })
      if (url.startsWith('/api/sboms/101/component-page?')) return response({ items: [], total: 0, limit: 50, offset: 0 })
      return response([])
    }))
  })
  afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('최근 분석 배열에 없는 두 분석을 단건 조회해 비교하고 돌아오면 선택 범위를 유지한다', async () => {
    await openProject(); selectPair()
    fireEvent.click(screen.getByRole('button', { name: '선택한 두 검사 비교' }))
    await screen.findByRole('heading', { name: '검사 기록 · 검사 전후 비교' })
    expect(screen.getByLabelText('이전 검사')).toHaveValue('1')
    expect(screen.getByLabelText('이후 검사')).toHaveValue('205')
    expect(fetch.mock.calls.some(([url]) => url === '/api/analyses/runs/1')).toBe(true)
    expect(fetch.mock.calls.some(([url]) => url === '/api/analyses/runs/205')).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: '검사 전후 비교', exact: true }))
    await screen.findByRole('table', { name: '검사 전후 CVE 비교' })
    fireEvent.click(screen.getByRole('button', { name: '검사 이력으로 돌아가기' }))
    await screen.findByText('검사 #1', { selector: 'strong' })
    expect(screen.getByRole('heading', { name: 'VM-001 · 소스 ZIP · orders' })).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '선택한 프로젝트' })).getByText('검사 #205 · CVE 0건')).toBeInTheDocument()
  })

  it('비교 준비 연타를 막고 다른 화면으로 이동하면 단건 조회를 중단해 늦은 응답을 버린다', async () => {
    const finish = []
    runRequest = (url) => new Promise((resolve) => finish.push(() => resolve(response(url.endsWith('/1') ? base : target))))
    await openProject(); selectPair()
    const compare = screen.getByRole('button', { name: '선택한 두 검사 비교' })
    fireEvent.click(compare); fireEvent.click(compare)
    expect(screen.getByRole('button', { name: '비교 준비 중…' })).toBeDisabled()
    const reads = fetch.mock.calls.filter(([url]) => url.startsWith('/api/analyses/runs/'))
    expect(reads).toHaveLength(2)
    fireEvent.click(screen.getByRole('button', { name: /인프라 검사/ }))
    expect(reads.every(([, options]) => options.signal.aborted)).toBe(true)
    await act(async () => finish.forEach((resolve) => resolve()))
    expect(screen.getByRole('heading', { name: '인프라 검사' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '검사 기록 · 검사 전후 비교' })).not.toBeInTheDocument()
  })

  it('프로젝트에서 오래된 CVE 결과·SBOM 상세를 왕복하고 대상 조치 필터를 이어받는다', async () => {
    await openProject()
    fireEvent.click(within(screen.getByText('검사 #1', { selector: 'strong' }).closest('tr')).getByRole('button', { name: 'CVE 결과' }))
    await waitFor(() => expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('101'))
    fireEvent.click(screen.getByRole('button', { name: '이 결과의 의존성 목록 보기' }))
    await screen.findByRole('heading', { name: 'SBOM #101 의존성 목록' })
    fireEvent.click(screen.getByRole('button', { name: '이 SBOM의 CVE 보기' }))
    await waitFor(() => expect(screen.getByLabelText('확인할 SBOM')).toHaveValue('101'))
    openHistoryView('검사 이력')
    fireEvent.click(await screen.findByRole('button', { name: '이 대상의 조치 목록' }))
    await screen.findByRole('region', { name: 'CVE 조치 목록' })
    expect(screen.getByLabelText('대상')).toHaveValue('7')
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerability-work?status=OPEN&limit=25&offset=0&asset_id=7')).toBe(true))
    fireEvent.click(screen.getByRole('button', { name: /개요/ }))
    openHistoryView('조치 목록')
    expect(screen.getByLabelText('대상')).toHaveValue('7')
    expect(fetch.mock.calls.some(([url]) => url === '/api/vulnerabilities')).toBe(false)
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })
})

describe('서버 분석 전후 비교', () => {
  const base = { id: 10, sbom_id: 110, asset_id: 7, asset_tag: 'VM-001', asset_name: '시연 서버', scan_scope: 'demo-python-venv', imported_at: '2026-09-15T06:00:00Z', scanner: 'grype' }
  const target = { ...base, id: 20, sbom_id: 120, imported_at: '2026-09-15T07:00:00Z' }
  const finding = { cve_id: 'CVE-2018-18074', component_name: 'requests', status: 'NO_LONGER_DETECTED', before_versions: ['2.19.1'], after_versions: ['2.32.5'], fixed_versions: ['2.20.0'], severity: 'HIGH' }
  let comparison
  let compareResponse
  let reportResponse
  let downloadedFiles
  let pdfBlob
  let jsonBlob

  function response(body) { return { ok: true, status: 200, json: async () => body } }
  async function openComparison() {
    localStorage.setItem('eolwatch_token', 'token')
    localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'viewer', role: 'VIEWER' }))
    let view
    await act(async () => { view = render(<App />) })
    openHistoryView('CVE 결과·조치')
    return view
  }
  function selectPair(baseId = '10', targetId = '20') {
    fireEvent.change(screen.getByLabelText('이전 검사'), { target: { value: baseId } })
    fireEvent.change(screen.getByLabelText('이후 검사'), { target: { value: targetId } })
  }
  async function runComparison() {
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검사 전후 비교', exact: true })) })
  }

  beforeEach(() => {
    localStorage.clear()
    comparison = { base, target, comparable: true, warnings: [], summary: { persistent: 0, new: 0, no_longer_detected: 1, component_removed: 0 }, findings: [finding] }
    compareResponse = null
    reportResponse = null; downloadedFiles = []
    pdfBlob = new Blob(['%PDF-verification'], { type: 'application/pdf' })
    jsonBlob = new Blob([JSON.stringify({ base_id: 10, target_id: 20 })], { type: 'application/json' })
    const OriginalURL = URL
    vi.stubGlobal('URL', class extends OriginalURL {
      static createObjectURL = vi.fn(() => 'blob:eolwatch-report')
      static revokeObjectURL = vi.fn()
    })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function () { downloadedFiles.push({ filename: this.download, href: this.href }) })
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (url.startsWith('/api/reports/analyses/')) return reportResponse ? reportResponse(url) : { ok: true, status: 200, blob: async () => url.endsWith('.pdf') ? pdfBlob : jsonBlob }
      if (/\/analyses\/\d+\/compare\/\d+$/.test(url)) return compareResponse ? compareResponse(url) : response(comparison)
      if (url === '/api/analyses') return response([base, target, { ...base, id: 5 }, { ...base, id: 30, scan_scope: 'ubuntu-dpkg-installed' }, { ...base, id: 40, asset_id: 8, asset_tag: 'VM-002' }, { ...base, id: 50 }, { ...base, id: 60, asset_id: null }])
      if (url === '/api/dashboard/summary') return response({ assets: 1, software_products: 0, sbom_documents: 0, components: 0, lifecycle_risk: {}, sbom_quality: { average_score: 0 }, urgent_items: [] })
      return response([])
    }))
  })
  afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('같은 대상·범위의 더 나중 분석만 비교 대상으로 선택할 수 있다', async () => {
    await openComparison()
    const button = screen.getByRole('button', { name: '검사 전후 비교', exact: true })
    expect(button).toBeDisabled()
    expect(screen.getByLabelText('이후 검사')).toBeDisabled()
    fireEvent.change(screen.getByLabelText('이전 검사'), { target: { value: '10' } })
    const options = within(screen.getByLabelText('이후 검사')).getAllByRole('option').map((option) => option.value)
    expect(options).toEqual(['', '20', '50'])
    expect(within(screen.getByLabelText('이전 검사')).getAllByRole('option').some((option) => option.value === '60')).toBe(false)
    fireEvent.change(screen.getByLabelText('이후 검사'), { target: { value: '20' } })
    expect(button).toBeEnabled()
    fireEvent.change(screen.getByLabelText('이전 검사'), { target: { value: '50' } })
    expect(screen.getByLabelText('이후 검사')).toHaveValue('')
    expect(within(screen.getByLabelText('이후 검사')).getAllByRole('option').map((option) => option.value)).toEqual(['', '20'])
    expect(screen.getByLabelText('이후 검사')).toBeEnabled()
    expect(button).toBeDisabled()
    expect(fetch.mock.calls.some(([url]) => url.includes('/compare/'))).toBe(false)
  })

  it('조회자도 변경 버전·검출 상태를 비교하고 조치 상태를 자동 변경하지 않는다', async () => {
    comparison.findings = [finding, { ...finding, cve_id: 'CVE-2025-11111', component_name: 'urllib3', status: 'PERSISTENT' }, { ...finding, cve_id: 'CVE-2025-22222', component_name: 'flask', status: 'NEW', before_versions: [] }, { ...finding, cve_id: 'CVE-2025-33333', component_name: 'removed-library', status: 'COMPONENT_REMOVED', after_versions: [] }]
    comparison.summary = { persistent: 1, new: 1, no_longer_detected: 1, component_removed: 1 }
    comparison.warnings = ['취약점 DB 기준 시각이 다릅니다.']
    await openComparison(); selectPair(); await runComparison()
    const call = fetch.mock.calls.find(([url]) => url === '/api/analyses/10/compare/20')
    expect(call).toBeDefined()
    expect(call[1].headers.get('Authorization')).toBe('Bearer token')
    const table = within(screen.getByRole('table', { name: '검사 전후 CVE 비교' }))
    const row = within(table.getByText('requests').closest('tr'))
    expect(row.getByText('2.19.1')).toBeInTheDocument()
    expect(row.getByText('2.32.5')).toBeInTheDocument()
    expect(row.getByText('2.20.0')).toBeInTheDocument()
    for (const status of ['재검사 미검출', '계속 검출', '새로 검출', '구성요소 제거']) expect(table.getByText(status)).toBeInTheDocument()
    expect(screen.getByText(/미검출이 곧 조치 완료는 아닙니다/)).toBeInTheDocument()
    expect(screen.getByText('취약점 DB 기준 시각이 다릅니다.')).toBeInTheDocument()
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
    expect(table.queryByRole('combobox')).not.toBeInTheDocument()
  })

  it('선택을 변경하면 진행 중 비교를 취소하고 이전 응답을 버린다', async () => {
    let resolveFirst
    compareResponse = (url) => url === '/api/analyses/10/compare/20' ? new Promise((resolve) => { resolveFirst = resolve }) : response({ ...comparison, target: { ...target, id: 50 }, findings: [{ ...finding, component_name: 'latest-result' }] })
    await openComparison(); selectPair(); await runComparison()
    const previousSignal = fetch.mock.calls.find(([url]) => url === '/api/analyses/10/compare/20')[1].signal
    fireEvent.change(screen.getByLabelText('이후 검사'), { target: { value: '50' } })
    expect(previousSignal.aborted).toBe(true)
    await runComparison()
    expect(screen.getByText('latest-result')).toBeInTheDocument()
    await act(async () => { resolveFirst(response(comparison)) })
    expect(screen.getByText('latest-result')).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: '검사 전후 CVE 비교' })).queryByText('requests')).not.toBeInTheDocument()
  })

  it('비교 결과를 100개씩 표시하고 분석 선택을 바꾸면 이전 결과와 페이지를 비운다', async () => {
    comparison.findings = Array.from({ length: 101 }, (_, index) => ({ ...finding, cve_id: `CVE-2026-${10000 + index}` }))
    await openComparison(); selectPair(); await runComparison()
    let table = within(screen.getByRole('table', { name: '검사 전후 CVE 비교' }))
    expect(table.getAllByRole('row')).toHaveLength(101)
    expect(table.getByText('CVE-2026-10000')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '비교 다음 페이지' }))
    expect(table.getAllByRole('row')).toHaveLength(2)
    expect(table.getByText('CVE-2026-10100')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('이후 검사'), { target: { value: '50' } })
    expect(screen.queryByRole('table', { name: '검사 전후 CVE 비교' })).not.toBeInTheDocument()
    await runComparison()
    table = within(screen.getByRole('table', { name: '검사 전후 CVE 비교' }))
    expect(table.getByText('CVE-2026-10000')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '비교 이전 페이지' })).toBeDisabled()
  })

  it('분석 조건이 다르면 주의사항과 함께 원본 보고서의 탐지 변화를 표시한다', async () => {
    comparison.comparable = false
    comparison.warnings = ['두 검사의 수집 조건을 확인하세요.']
    await openComparison(); selectPair(); await runComparison()
    expect(screen.getByRole('status')).toHaveTextContent('검사 조건이 달라 단순 비교가 어렵습니다. 아래는 원본 보고서의 변화입니다.')
    expect(screen.getByText('두 검사의 수집 조건을 확인하세요.')).toBeInTheDocument()
    const table = within(screen.getByRole('table', { name: '검사 전후 CVE 비교' }))
    expect(table.getByText('재검사 미검출')).toBeInTheDocument()
    expect(table.getByText('2.19.1')).toBeInTheDocument()
    expect(table.getByText('2.32.5')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '검증 보고서 PDF' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '검증 데이터 JSON' })).toBeEnabled()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 보고서 PDF' })) })
    expect(downloadedFiles[0].filename).toBe('eolwatch-analysis-10-20.pdf')
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })

  it('표시한 분석 쌍의 PDF와 JSON을 인증 요청해 올바른 파일명으로 내려받는다', async () => {
    await openComparison()
    expect(screen.queryByRole('button', { name: '검증 보고서 PDF' })).not.toBeInTheDocument()
    selectPair(); await runComparison()
    expect(screen.getByText('범위·도구·원본 정보와 CVE 전후 결과가 담깁니다.')).toBeInTheDocument()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 보고서 PDF' })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 데이터 JSON' })) })
    const calls = fetch.mock.calls.filter(([url]) => url.startsWith('/api/reports/analyses/'))
    expect(calls.map(([url]) => url)).toEqual(['/api/reports/analyses/10/compare/20.pdf', '/api/reports/analyses/10/compare/20.json'])
    expect(calls.every(([, options]) => new Headers(options.headers).get('Authorization') === 'Bearer token' && !options.method)).toBe(true)
    expect(downloadedFiles).toEqual([{ filename: 'eolwatch-analysis-10-20.pdf', href: 'blob:eolwatch-report' }, { filename: 'eolwatch-analysis-10-20.json', href: 'blob:eolwatch-report' }])
    expect(URL.createObjectURL).toHaveBeenNthCalledWith(1, pdfBlob)
    expect(URL.createObjectURL).toHaveBeenNthCalledWith(2, jsonBlob)
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('button', { name: '검증 보고서 PDF' })).toBeEnabled()
  })

  it('다운로드 중 중복 요청을 막고 오류 원인을 표시한 뒤 재시도를 허용한다', async () => {
    let resolveReport
    reportResponse = () => new Promise((resolve) => { resolveReport = resolve })
    await openComparison(); selectPair(); await runComparison()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 보고서 PDF' })) })
    expect(screen.getByRole('button', { name: '검증 보고서 PDF' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '검증 데이터 JSON' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '검증 데이터 JSON' }))
    expect(fetch.mock.calls.filter(([url]) => url.startsWith('/api/reports/analyses/'))).toHaveLength(1)
    await act(async () => { resolveReport({ ok: false, status: 503, json: async () => ({ detail: '원본 보고서를 준비하지 못했습니다.' }) }) })
    expect(screen.getByRole('alert')).toHaveTextContent('검증 보고서 PDF 다운로드 실패: 원본 보고서를 준비하지 못했습니다.')
    expect(downloadedFiles).toHaveLength(0)
    expect(screen.getByRole('button', { name: '검증 보고서 PDF' })).toBeEnabled()
    reportResponse = null
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 데이터 JSON' })) })
    expect(downloadedFiles[0].filename).toBe('eolwatch-analysis-10-20.json')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('선택을 바꾸면 이전 파일 응답을 취소하고 새 분석 쌍의 보고서만 내려받는다', async () => {
    let resolveBlob
    reportResponse = () => ({ ok: true, status: 200, blob: () => new Promise((resolve) => { resolveBlob = resolve }) })
    await openComparison(); selectPair(); await runComparison()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 보고서 PDF' })) })
    const signal = fetch.mock.calls.find(([url]) => url.endsWith('/compare/20.pdf'))[1].signal
    fireEvent.change(screen.getByLabelText('이후 검사'), { target: { value: '50' } })
    expect(signal.aborted).toBe(true)
    expect(screen.queryByRole('button', { name: '검증 보고서 PDF' })).not.toBeInTheDocument()
    comparison.target = { ...target, id: 50 }
    await runComparison()
    reportResponse = null
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 데이터 JSON' })) })
    await act(async () => { resolveBlob(pdfBlob) })
    expect(downloadedFiles).toEqual([{ filename: 'eolwatch-analysis-10-50.json', href: 'blob:eolwatch-report' }])
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: '검증 데이터 JSON' })).toBeEnabled()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('비교 화면을 벗어나면 보고서 요청을 취소하고 늦은 파일을 내려받지 않는다', async () => {
    let resolveReport
    reportResponse = () => new Promise((resolve) => { resolveReport = resolve })
    await openComparison(); selectPair(); await runComparison()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '검증 보고서 PDF' })) })
    const signal = fetch.mock.calls.find(([url]) => url.endsWith('/compare/20.pdf'))[1].signal
    fireEvent.click(screen.getByRole('button', { name: /인프라 검사/ }))
    expect(signal.aborted).toBe(true)
    await act(async () => { resolveReport({ ok: true, status: 200, blob: async () => pdfBlob }) })
    expect(downloadedFiles).toHaveLength(0)
    expect(URL.createObjectURL).not.toHaveBeenCalled()
  })

  it('비교 화면을 벗어나면 진행 중 요청을 취소한다', async () => {
    let resolveComparison
    compareResponse = () => new Promise((resolve) => { resolveComparison = resolve })
    await openComparison(); selectPair(); await runComparison()
    const signal = fetch.mock.calls.find(([url]) => url.includes('/compare/'))[1].signal
    fireEvent.click(screen.getByRole('button', { name: /인프라 검사/ }))
    expect(signal.aborted).toBe(true)
    await act(async () => { resolveComparison(response(comparison)) })
    expect(screen.queryByRole('table', { name: '검사 전후 CVE 비교' })).not.toBeInTheDocument()
  })
})

describe('검사 원본 보기', () => {
  afterEach(() => { cleanup(); vi.unstubAllGlobals() })
  it('원본 보기는 먼저 화면에 JSON을 보여주고 거기서 다운로드한다', async () => {
    localStorage.setItem('eolwatch_token', 'token'); localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'viewer', role: 'VIEWER' }))
    const run = { id: 20, sbom_id: 12, asset_id: 7, asset_tag: 'VM-001', asset_name: '서버', scan_scope: 'source-zip:orders', imported_at: '2026-09-15T06:00:00Z', cve_count: 1, component_count: 2, scanner: 'Grype', scanner_version: '0.118.0', link_count: 1, match_count: 1, ignored_non_cve: 0 }
    const bundle = { sbom: { spdxVersion: 'SPDX-2.3', packages: [{ name: 'a' }, { name: 'b' }] }, report: { matches: [{ vulnerability: { id: 'CVE-2025-1' } }] }, scan_scope: run.scan_scope }
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      const json = (body) => ({ ok: true, status: 200, json: async () => body, blob: async () => new Blob([JSON.stringify(body)]) })
      if (url === '/api/dashboard/summary') return json({ assets: 1, sbom_documents: 1, components: 2, open_cves: 1, affected_assets: 1, failed_checks_24h: 0, sbom_quality: { average_score: 90 }, latest_analyses: [] })
      if (url === '/api/analyses') return json([run])
      if (url === '/api/sboms') return json([{ id: 12, component_count: 2 }])
      if (url === '/api/analyses/20/bundle') return json(bundle)
      if (url.startsWith('/api/vulnerability-work?')) return json({ items: [], total: 0, limit: 100, offset: 0 })
      if (url.startsWith('/api/ai/')) return json({ enabled: false, provider: 'openai', model: 'gpt-5-mini' })
      return json([])
    }))
    vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(() => 'blob:x'), revokeObjectURL: vi.fn() })
    render(<App />)
    await screen.findByText('검사 대상')
    openHistoryView('CVE 결과·조치')
    fireEvent.click(await screen.findByRole('button', { name: '검사 20 원본 보기' }))
    const viewer = await screen.findByRole('region', { name: '검사 원본' })
    await within(viewer).findByLabelText('원본 JSON 내용')
    expect(within(viewer).getByText(/구성요소 2개 · 탐지 1건/)).toBeInTheDocument()
    expect(within(viewer).getByLabelText('원본 JSON 내용')).toHaveTextContent('CVE-2025-1')
    expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/20/bundle')).toHaveLength(1)
    fireEvent.click(within(viewer).getByRole('button', { name: 'JSON 다운로드' }))
    await waitFor(() => expect(fetch.mock.calls.filter(([url]) => url === '/api/analyses/20/bundle')).toHaveLength(2))
    fireEvent.click(within(viewer).getByRole('button', { name: '닫기' }))
    expect(screen.queryByRole('region', { name: '검사 원본' })).not.toBeInTheDocument()
  })
})

describe('파이프라인 AI 표시', () => {
  afterEach(() => { cleanup(); vi.unstubAllGlobals() })
  const agent = { source: 'ai', model: 'gpt-5-mini', note: 'AWS의 Ubuntu 웹 서버', cached: false, input_tokens: 412, output_tokens: 57,
    results: [{ id: 'apt_upgradable', purpose: 'apt로 미적용 보안 업데이트 확인', reason: 'Ubuntu라 apt를 쓴다', command: 'apt list --upgradable', ok: true, output: 'openssl/jammy-updates 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]' },
      { id: 'firewall', purpose: '방화벽 활성 여부와 규칙 요약', reason: '외부 노출 서버', command: 'ufw status', ok: false, output: 'ufw: command not found' }] }
  const check = { id: 31, asset_id: 7, asset_tag: 'srv-han', asset_name: '성민 서버', status: 'SUCCESS', started_at: '2026-09-21T09:00:00Z', cpu_percent: 3, memory_percent: 40, max_disk_percent: 55, health_level: 'OK',
    server_info: { hostname: 'ip-10-0-1-5', os_name: 'Ubuntu 22.04.4 LTS', architecture: 'x86_64', platform: 'aws', services: ['ssh.service'], listening_ports: [{ port: 22 }], ai_collection: agent } }
  const run = { id: 40, sbom_id: 9, asset_tag: 'GH-app', asset_name: 'GitHub app', scanner: 'grype', scanner_version: '0.118.0', generator: 'EOLWatch-AI-Library-Reference, gpt-5-mini', scan_scope: 'source-git:app', component_count: 6, match_count: 2, cve_count: 2, link_count: 2, ignored_non_cve: 0, fixable_cve_count: 1, kernel_cve_count: 0, imported_at: '2026-09-21T09:10:00Z', database_info: {} }
  function setup(data) {
    localStorage.clear(); localStorage.setItem('eolwatch_token', 'token'); localStorage.setItem('eolwatch_user', JSON.stringify({ id: 1, username: 'operator', role: 'ADMIN' }))
    vi.stubGlobal('fetch', vi.fn(async (url) => ({ ok: true, status: 200, json: async () => (url in data ? data[url] : (url.startsWith('/api/ai/') ? null : [])) })))
  }
  it('SSH 점검의 서버 정보에 수집 에이전트가 고른 점검과 출력을 보여준다', async () => {
    setup({ '/api/dashboard/summary': { assets: 1, lifecycle_risk: {}, sbom_quality: {}, urgent_items: [] }, '/api/assets': [{ id: 7, asset_tag: 'srv-han', name: '성민 서버', ip_address: '3.36.62.90', ssh_username: 'ubuntu', monitored: true }], '/api/checks': [check], '/api/ai/status': { enabled: false } })
    render(<App />)
    await screen.findByText('검사 대상')
    fireEvent.click(screen.getByRole('button', { name: /인프라 검사/ }))
    fireEvent.click(await screen.findByRole('button', { name: '점검 31 서버 정보' }))
    expect(screen.getByText(/AI\(gpt-5-mini\)가 이 서버에 맞춰 고른 점검 2개/)).toBeInTheDocument()
    expect(screen.getByText(/토큰 412\/57/)).toBeInTheDocument()
    expect(screen.getByText('외부 노출 서버 · 실행 실패')).toBeInTheDocument()
    expect(screen.queryByText(/upgradable from/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'apt로 미적용 보안 업데이트 확인' }))
    expect(screen.getByText(/upgradable from: 3\.0\.2-0ubuntu1\.15/)).toBeInTheDocument()
    expect(screen.getByText('apt list --upgradable')).toBeInTheDocument()
  })
  it('AI가 라이브러리를 추정한 검사 결과에는 버전 추정 표시가 붙는다', async () => {
    setup({ '/api/dashboard/summary': { assets: 0, lifecycle_risk: {}, sbom_quality: {}, urgent_items: [] }, '/api/analyses': [run], '/api/sboms': [{ id: 9, component_count: 6 }], '/api/ai/status': { enabled: false } })
    render(<App />)
    await screen.findByText('검사 대상')
    openHistoryView('CVE 결과·조치')
    await screen.findByRole('heading', { name: '최근 검사 결과' })
    expect(screen.getByText('AI 라이브러리 참조 · 버전 추정')).toBeInTheDocument()
    expect(screen.getByText('지금 고칠 수 있는 CVE 1개')).toBeInTheDocument()
    expect(screen.getByText(/수정판 없음 1개 · 전체 CVE 2개 · 구성요소 연결 2건/)).toBeInTheDocument()
  })
})
