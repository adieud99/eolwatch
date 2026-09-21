import { useCallback, useEffect, useRef, useState } from 'react'
import VulnerabilityActions from './VulnerabilityActions'
import VulnerabilityWorklist from './VulnerabilityWorklist'
import SbomExplorer from './SbomExplorer'
import AnalysisTargets, { scopeLabel } from './AnalysisTargets'
import AssetEditor from './AssetEditor'
import ProjectHub from './ProjectHub'

const EMPTY_SUMMARY = {
  assets: 0,
  sbom_documents: 0,
  components: 0,
  dependencies: 0,
  open_cves: 0,
  affected_assets: 0,
  failed_checks_24h: 0,
  sbom_quality: { average_score: 0, below_70: 0 },
  latest_analyses: [],
}

const typeText = { server: '서버', storage: '스토리지', network: '네트워크', security: '보안장비', vm: '가상머신', cloud: '클라우드', other: '기타' }
const analysisJobText = { QUEUED: '대기', COLLECTING: '수집', SCANNING: '분석', IMPORTING: '저장', SUCCESS: '완료', FAILED: '실패', CANCEL_REQUESTED: '취소 중', CANCELLED: '취소됨' }
const analysisScopeText = { 'ubuntu-dpkg-installed': 'OS · 설치 패키지', 'demo-python-venv': '데모 앱 · Python' }
const comparisonStatusText = { PERSISTENT: '계속 검출', NEW: '새로 검출', NO_LONGER_DETECTED: '재검사 미검출', COMPONENT_REMOVED: '구성요소 제거' }
const vexStatusText = { AFFECTED: '영향 있음', NOT_AFFECTED: '영향 없음', FIXED: '조치 완료', UNDER_INVESTIGATION: '조사 중' }
const activeAnalysisJob = (job) => ['QUEUED', 'COLLECTING', 'SCANNING', 'IMPORTING', 'CANCEL_REQUESTED'].includes(job.status)
const isZipScope = (scope = '') => scope.startsWith('source-zip')
const tabTitles = { overview: '개요', dev: '개발 검사 · 소스 ZIP', infra: '인프라 검사 · 서버', history: '검사 기록', admin: '관리' }
const historyTitles = { projects: '검사 이력', cve: 'CVE 결과·조치', work: '조치 작업목록', sbom: '의존성 목록', comparison: '검사 전후 비교' }

async function api(path, options) {
  const headers = new Headers(options?.headers || {})
  const token = localStorage.getItem('eolwatch_token')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`/api${path}`, { ...options, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const error = new Error(typeof body.detail === 'string' ? body.detail : '요청을 처리하지 못했습니다.')
    error.status = response.status
    throw error
  }
  if (response.status === 204) return null
  return response.json()
}

async function download(path, filename, signal) {
  const token = localStorage.getItem('eolwatch_token')
  const response = await fetch(`/api${path}`, { headers: { Authorization: `Bearer ${token}` }, signal })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(typeof body.detail === 'string' ? body.detail : '보고서를 내려받지 못했습니다.')
  }
  const blob = await response.blob()
  if (signal?.aborted) return
  const url = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = url; anchor.download = filename; anchor.click()
  } finally { URL.revokeObjectURL(url) }
}

function Login({ onLogin }) {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      const data = Object.fromEntries(new FormData(event.currentTarget))
      const result = await api('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      localStorage.setItem('eolwatch_token', result.access_token)
      localStorage.setItem('eolwatch_user', JSON.stringify(result.user))
      onLogin(result.user)
    } catch (reason) { setError(reason.message) }
    finally { setBusy(false) }
  }
  return (
    <main className="login-page">
      <section className="login-card">
        <div className="brand login-brand"><span className="brand-mark">E</span><div><strong>EOLWatch</strong><small>Dev &amp; Infra Vulnerability Scan</small></div></div>
        <span className="eyebrow">SECURE ACCESS</span><h1>개발·인프라 취약점 검사</h1>
        <p>승인된 운영 계정으로 로그인하세요.</p>
        <form className="vertical-form" onSubmit={submit}>
          <label>아이디<input name="username" autoComplete="username" required /></label>
          <label>비밀번호<input name="password" type="password" autoComplete="current-password" required minLength="8" /></label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary" disabled={busy}>{busy ? '확인 중…' : '로그인'}</button>
        </form>
      </section>
    </main>
  )
}

function Metric({ label, value, detail }) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  )
}

function Overview({ summary, onViewResult, analysisJobs }) {
  const latest = new Map((summary.latest_analyses || []).map((item) => [`${item.asset_id}-${item.scan_scope}`, item]))
  for (const job of analysisJobs) {
    const scope = job.scan_scope || 'ubuntu-dpkg-installed'
    const key = `${job.asset_id}-${scope}`
    const previous = latest.get(key) || { asset_id: job.asset_id, asset_tag: job.asset_tag, asset_name: job.asset_name, scan_scope: scope }
    const requestTime = new Date(job.requested_at).getTime()
    const previousTime = previous.latest_attempt_requested_at ? new Date(previous.latest_attempt_requested_at).getTime() : -Infinity
    if (requestTime < previousTime || (requestTime === previousTime && job.id < previous.latest_attempt_id)) continue
    latest.set(key, { ...previous, latest_attempt_id: job.id, latest_attempt_status: job.status, latest_attempt_requested_at: job.requested_at, latest_attempt_finished_at: job.finished_at, latest_attempt_is_newer: !previous.last_success_at || requestTime > new Date(previous.last_success_at).getTime() })
  }
  const hasCurrent = summary.current_open_cves != null
  return (
    <>
      <section className="metric-grid">
        <Metric label="등록 서버" value={summary.assets} detail="인프라 검사 대상" />
        <Metric label="현재 검사의 미조치 CVE" value={hasCurrent ? summary.current_open_cves : '미확인'} detail={hasCurrent ? `서버·범위별 마지막 검사 기준 · ${summary.current_affected_assets ?? 0}대` : '현재 검사 집계 정보 없음'} />
        <Metric label="누적 미조치 CVE" value={summary.open_cves ?? 0} detail={`전체 검사 이력 기준 · ${summary.affected_assets ?? 0}대`} />
        <Metric label="최근 수집 실패" value={summary.failed_checks_24h ?? 0} detail="최근 24시간" />
        <Metric label="의존성 목록 (SBOM)" value={summary.sbom_documents} detail={`${summary.components}개 구성요소 · 품질 ${summary.sbom_quality.average_score}%`} />
      </section>

      <section className="panel full-panel compare-panel">
        <div className="panel-heading"><div><span className="eyebrow">LATEST SCAN BY TARGET</span><h2>대상·범위별 최근 검사</h2><small>마지막으로 성공한 검사 당시의 CVE 수입니다. 소스 ZIP 검사와 서버 검사를 범위로 구분하며, 수동 조치 상태와 별도로 표시합니다.</small></div></div>
        <div className="table-wrap"><table aria-label="대상·범위별 최근 검사"><thead><tr><th>대상</th><th>검사 범위</th><th>마지막 성공 검사</th><th>탐지 CVE</th><th>최근 검사 요청</th><th>확인</th></tr></thead><tbody>
          {[...latest.values()].map((item) => <tr key={`${item.asset_id}-${item.scan_scope}`}>
            <td><strong>{item.asset_tag}</strong><small>{item.asset_name}</small></td>
            <td>{analysisScopeText[item.scan_scope] || scopeLabel(item.scan_scope)}</td>
            <td>{item.analysis_run_id ? <><strong>검사 #{item.analysis_run_id} · SBOM #{item.sbom_id}</strong><small>{new Date(item.last_success_at).toLocaleString('ko-KR')}</small></> : '성공한 검사 없음'}</td>
            <td><strong>{item.cve_count == null ? '미확인' : `${item.cve_count}개`}</strong>{item.cve_count === 0 && <small>해당 범위·검사 시점에서 미검출</small>}</td>
            <td>{item.latest_attempt_id ? <><span className={`job job-${item.latest_attempt_status === 'SUCCESS' ? 'success' : item.latest_attempt_status === 'FAILED' ? 'failed' : item.latest_attempt_status === 'CANCELLED' ? 'cancelled' : 'running'}`}>{analysisJobText[item.latest_attempt_status] || item.latest_attempt_status}</span><small>작업 #{item.latest_attempt_id} · 요청 {new Date(item.latest_attempt_requested_at).toLocaleString('ko-KR')}</small>{item.latest_attempt_finished_at && <small>종료 {new Date(item.latest_attempt_finished_at).toLocaleString('ko-KR')}</small>}{item.latest_attempt_is_newer && item.latest_attempt_status !== 'SUCCESS' && <small>{item.analysis_run_id ? item.latest_attempt_status === 'FAILED' ? '최근 재검사에 실패했습니다. 마지막 성공 검사를 표시합니다.' : item.latest_attempt_status === 'CANCELLED' ? '최근 재검사를 취소했습니다. 마지막 성공 검사를 표시합니다.' : item.latest_attempt_status === 'CANCEL_REQUESTED' ? '재검사 취소를 처리 중입니다. 마지막 성공 검사를 표시합니다.' : '재검사 진행 중입니다. 마지막 성공 검사를 표시합니다.' : '완료된 검사 결과가 없습니다.'}</small>}</> : <small>검사 요청 이력 없음</small>}</td>
            <td><button className="table-button" aria-label={`${item.asset_tag} ${analysisScopeText[item.scan_scope] || scopeLabel(item.scan_scope)} 최근 검사 결과 보기`} disabled={!item.sbom_id} onClick={() => onViewResult(item.sbom_id)}>결과 보기</button></td>
          </tr>)}
          {!latest.size && <tr><td colSpan="6" className="empty">아직 검사 이력이 없습니다. 개발 검사에서 소스 ZIP을 올리거나 인프라 검사에서 서버를 등록하세요.</td></tr>}
        </tbody></table></div>
      </section>
    </>
  )
}

function Servers({ assets, onChanged, canEdit, analysisJobs, pendingAssets, onStartAnalysis, focusedAssetId, onViewProjects, onViewCve, onViewSbom }) {
  const [editing, setEditing] = useState(null)
  const [assetQuery, setAssetQuery] = useState('')
  useEffect(() => { if (focusedAssetId) setEditing(assets.find((asset) => asset.id === focusedAssetId) || null) }, [focusedAssetId])
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const [scanScopes, setScanScopes] = useState({})
  async function submit(event) {
    const form = event.currentTarget
    event.preventDefault()
    setError('')
    const data = Object.fromEntries(new FormData(form))
    for (const key of ['ip_address', 'ssh_username']) if (!data[key]) data[key] = null
    data.ssh_port = Number(data.ssh_port) || 22
    data.monitored = Boolean(data.monitored)
    try {
      await api('/assets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      form.reset()
      setOpen(false)
      onChanged('서버를 등록했습니다.')
    } catch (reason) { setError(reason.message) }
  }
  const visible = assets.filter((asset) => {
    const query = assetQuery.trim().toLowerCase()
    const searchable = [asset.asset_tag, asset.name, asset.ip_address, asset.ssh_username].filter(Boolean).join(' ').toLowerCase()
    return !query || searchable.includes(query)
  })
  return (
    <section className="panel full-panel">
      {editing && <AssetEditor key={editing.id} asset={editing} canEdit={canEdit} request={api} onViewCve={onViewCve} onViewSbom={onViewSbom} onSaved={(updated) => { setEditing(null); onChanged(updated ? '서버 정보를 저장했습니다.' : '사용하지 않는 서버를 삭제했습니다.') }} onClose={() => setEditing(null)} />}
      <div className="panel-heading">
        <div><span className="eyebrow">INFRASTRUCTURE SCAN</span><h2>검사 대상 서버</h2><small>서버 IP와 SSH 계정을 등록하면 검사 도구를 서버에 복사해 실행하고 설치 패키지와 서버 정보를 수집합니다.</small></div>
        <div className="action-row">
          {canEdit && <button className="primary" onClick={() => setOpen(!open)}>{open ? '닫기' : '+ 서버 등록'}</button>}
        </div>
      </div>
      {open && (
        <form className="asset-form" onSubmit={submit}>
          <label>서버 번호<input name="asset_tag" required placeholder="SRV-001" /></label>
          <label>서버 이름<input name="name" required placeholder="운영 웹 서버" /></label>
          <label>유형<select name="asset_type" defaultValue="server">{Object.entries(typeText).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
          <label>서버 IP<input name="ip_address" placeholder="10.0.1.11" /></label>
          <label>SSH 포트<input name="ssh_port" type="number" min="1" max="65535" defaultValue="22" /></label>
          <label>SSH 계정<input name="ssh_username" placeholder="eolwatch" /></label>
          <label className="checkbox"><input type="checkbox" name="monitored" defaultChecked /> 검사 대상으로 사용</label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary submit" type="submit">저장</button>
        </form>
      )}
      <div className="management-search asset-search"><label>서버 검색<input value={assetQuery} maxLength={100} onChange={(event) => setAssetQuery(event.target.value)} placeholder="서버 이름, 번호, IP, 계정" /></label></div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>서버 번호</th><th>서버</th><th>구분</th><th>접속 정보</th><th>검사 결과</th><th>점검·검사</th></tr></thead>
          <tbody>
            {visible.map((asset) => {
              const activeJob = analysisJobs.find((job) => job.asset_id === asset.id && activeAnalysisJob(job))
              const pending = pendingAssets.includes(asset.id)
              const unavailable = !asset.monitored || !asset.ip_address || !asset.ssh_username
              return (
              <tr key={asset.id}>
                <td><code>{asset.asset_tag}</code></td>
                <td><strong>{asset.name}</strong><button className="table-button" aria-label={`${asset.asset_tag} 서버 ${canEdit ? '수정' : '상세'}`} onClick={() => setEditing(asset)}>{canEdit ? '수정' : '상세'}</button><button className="table-button" aria-label={`${asset.asset_tag} 검사 기록`} onClick={() => onViewProjects(asset.id)}>검사 기록</button></td>
                <td>{typeText[asset.asset_type] || asset.asset_type}</td>
                <td>{asset.ip_address ? <><strong>{asset.ip_address}:{asset.ssh_port}</strong><small>{asset.ssh_username || 'SSH 계정 미입력'}</small></> : <small>IP 미입력</small>}</td>
                <td>SBOM {asset.sbom_count ?? 0}<small>CVE {asset.vulnerability_count ?? 0}건</small></td>
                <td><label>검사 범위<select aria-label={`${asset.asset_tag} 검사 범위`} value={scanScopes[asset.id] || 'ubuntu-dpkg-installed'} disabled={!canEdit || unavailable || pending || Boolean(activeJob)} onChange={(event) => setScanScopes((current) => ({ ...current, [asset.id]: event.target.value }))}>{Object.entries(analysisScopeText).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><div className="action-row"><button className="table-button" disabled={!canEdit || !asset.ip_address || !asset.ssh_username} onClick={async () => {
                  try {
                    const job = await api(`/checks/assets/${asset.id}/run`, { method: 'POST' })
                    onChanged(job.status === 'SUCCESS' ? '서버 정보 수집을 완료했습니다.' : `수집 실패: ${job.failure_message}`)
                  } catch (reason) { onChanged(reason.message) }
                }}>SSH 점검</button><button className="table-button" aria-label={`${asset.asset_tag} 취약점 검사`} disabled={!canEdit || unavailable || pending || Boolean(activeJob)} title={!canEdit ? '관리자만 검사를 요청할 수 있습니다.' : unavailable ? '검사 대상 설정, 서버 IP와 SSH 계정이 필요합니다.' : activeJob ? `검사 작업 #${activeJob.id} 진행 중` : '설치 패키지를 수집한 뒤 취약점을 검사합니다.'} onClick={() => onStartAnalysis(asset.id, undefined, scanScopes[asset.id] || 'ubuntu-dpkg-installed')}>{pending ? '요청 중…' : activeJob ? `검사 진행 중 · ${analysisJobText[activeJob.status]}` : '취약점 검사'}</button></div>{unavailable && <small>검사에는 검사 대상 설정·IP·SSH 계정이 필요합니다.</small>}</td>
              </tr>
            )})}
            {!visible.length && <tr><td colSpan="6" className="empty">{assets.length ? '검색 조건에 맞는 서버가 없습니다.' : '등록된 서버가 없습니다. 서버 IP와 SSH 계정을 등록하세요.'}</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function Checks({ checks }) {
  return (
    <section className="panel full-panel">
      <div className="panel-heading"><div><span className="eyebrow">SERVER INFORMATION</span><h2>서버 정보 수집 이력</h2><small>SSH로 수집한 CPU·메모리·디스크 사용률과 OS 정보입니다.</small></div><span className="subtle">최근 {checks.length}건</span></div>
      <div className="table-wrap"><table aria-label="서버 정보 수집 이력">
        <thead><tr><th>실행 시각</th><th>서버</th><th>상태</th><th>CPU</th><th>메모리</th><th>디스크</th><th>결과</th></tr></thead>
        <tbody>{checks.map((job) => <tr key={job.id}>
          <td>{job.started_at ? new Date(job.started_at).toLocaleString('ko-KR') : '-'}</td>
          <td><strong>{job.asset_name}</strong><small>{job.asset_tag}</small></td>
          <td><span className={`job job-${job.status.toLowerCase()}`}>{job.status}</span></td>
          <td>{job.cpu_percent === null ? '-' : `${job.cpu_percent}%`}</td><td>{job.memory_percent === null ? '-' : `${job.memory_percent}%`}</td><td>{job.max_disk_percent === null ? '-' : `${job.max_disk_percent}%`}</td>
          <td>{job.health_level || job.failure_stage || '-'}<small>{job.failure_message}</small></td>
        </tr>)}{checks.length === 0 && <tr><td colSpan="7" className="empty">수집 이력이 없습니다. 서버 목록에서 SSH 점검을 실행할 수 있습니다.</td></tr>}</tbody>
      </table></div>
    </section>
  )
}

function AnalysisJobs({ jobs, error, pendingAssets, onRetry, onCancel, onViewResult, canEdit, title = '검사 작업', hint = '대기 → 수집 → 분석 → 저장 순서로 진행하며, 완료되면 결과를 확인할 수 있습니다.' }) {
  return <section className="panel full-panel">
    <div className="panel-heading"><div><span className="eyebrow">SCAN JOBS</span><h2>{title}</h2><small>{hint}</small></div><span className="subtle">최근 {jobs.length}건 · 자동 갱신</span></div>
    {error && <p className="inline-result form-error" role="alert">{error}</p>}
    <div className="table-wrap"><table aria-label={title}><thead><tr><th>요청 시각</th><th>대상</th><th>진행 상태</th><th>결과·오류</th><th>확인</th></tr></thead><tbody>
      {jobs.map((job) => <tr key={job.id}>
        <td>{new Date(job.requested_at).toLocaleString('ko-KR')}<small>작업 #{job.id}{job.retry_of_id ? ` · 작업 #${job.retry_of_id} 재시도` : ''}</small></td>
        <td><strong>{job.asset_tag || `서버 #${job.asset_id}`}</strong><small>{job.asset_name}</small><small>{analysisScopeText[job.scan_scope] || scopeLabel(job.scan_scope)}</small></td>
        <td><span className={`job job-${job.status === 'SUCCESS' ? 'success' : job.status === 'FAILED' ? 'failed' : 'running'}`}>{analysisJobText[job.status] || job.status}</span>{job.finished_at && <small>{new Date(job.finished_at).toLocaleString('ko-KR')}</small>}</td>
        <td>{job.error_message ? <><strong>{job.error_message}</strong>{job.error_code && <small>{job.error_code}</small>}</> : job.status === 'SUCCESS' ? <><strong>검사 #{job.analysis_run_id}</strong><small>SBOM #{job.sbom_id}</small></> : <small>{job.status === 'CANCELLED' ? '검사를 취소했습니다.' : job.status === 'CANCEL_REQUESTED' ? '실행 중인 프로세스 종료를 확인하고 있습니다.' : '진행 상태를 자동으로 확인합니다.'}</small>}</td>
        <td>{job.status === 'SUCCESS' && job.sbom_id && <button className="table-button" aria-label={`작업 ${job.id} 결과 보기`} onClick={() => onViewResult(job.sbom_id)}>결과 보기</button>}{job.status === 'FAILED' && <button className="table-button" aria-label={`작업 ${job.id} 재시도`} disabled={!canEdit || pendingAssets.includes(job.asset_id) || jobs.some((item) => item.asset_id === job.asset_id && activeAnalysisJob(item))} onClick={() => onRetry(job)}>재시도</button>}{canEdit && activeAnalysisJob(job) && <button className="table-button" aria-label={`작업 ${job.id} 취소`} disabled={job.status === 'CANCEL_REQUESTED' || pendingAssets.includes(job.asset_id)} onClick={() => onCancel(job)}>검사 취소</button>}</td>
      </tr>)}
      {!jobs.length && <tr><td colSpan="5" className="empty">요청한 검사가 없습니다.</td></tr>}
    </tbody></table></div>
  </section>
}

function AnalysisComparison({ analyses, initialBaseId = '', initialTargetId = '' }) {
  const [baseId, setBaseId] = useState(String(initialBaseId))
  const [targetId, setTargetId] = useState(String(initialTargetId))
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [downloading, setDownloading] = useState('')
  const [page, setPage] = useState(0)
  const request = useRef(null)
  const reportRequest = useRef(null)
  const revision = useRef(0)
  const base = analyses.find((run) => String(run.id) === baseId)
  const candidates = base?.asset_id != null && base.scan_scope ? analyses.filter((run) => run.asset_id === base.asset_id && run.scan_scope === base.scan_scope && (Date.parse(run.imported_at) > Date.parse(base.imported_at) || (run.imported_at === base.imported_at && run.id > base.id))) : []
  const target = candidates.find((run) => String(run.id) === targetId)
  const pageSize = 100
  const findings = result?.findings || []
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize))
  const currentPage = Math.min(page, pageCount - 1)
  const label = (run) => `#${run.id} · ${run.asset_tag || `서버 #${run.asset_id}`} · ${analysisScopeText[run.scan_scope] || scopeLabel(run.scan_scope)}`

  useEffect(() => () => { request.current?.abort(); reportRequest.current?.abort() }, [])

  function resetResult() {
    revision.current += 1; request.current?.abort(); reportRequest.current?.abort()
    setResult(null); setError(''); setBusy(false); setDownloading(''); setPage(0)
  }
  async function compare() {
    if (!base || !target || busy) return
    const controller = new AbortController()
    request.current?.abort(); request.current = controller
    reportRequest.current?.abort(); setDownloading('')
    const requestedRevision = ++revision.current
    setBusy(true); setError(''); setResult(null); setPage(0)
    try {
      const data = await api(`/analyses/${base.id}/compare/${target.id}`, { signal: controller.signal })
      if (!controller.signal.aborted && requestedRevision === revision.current) setResult(data)
    } catch (reason) {
      if (!controller.signal.aborted && requestedRevision === revision.current) setError(`검사 비교 실패: ${reason.message}`)
    } finally {
      if (!controller.signal.aborted && requestedRevision === revision.current) setBusy(false)
    }
  }

  async function downloadReport(format) {
    if (!result || downloading || (reportRequest.current && !reportRequest.current.signal.aborted)) return
    const controller = new AbortController()
    reportRequest.current = controller
    const requestedRevision = revision.current
    setDownloading(format); setError('')
    try {
      await download(`/reports/analyses/${result.base.id}/compare/${result.target.id}.${format}`, `eolwatch-analysis-${result.base.id}-${result.target.id}.${format}`, controller.signal)
    } catch (reason) {
      if (!controller.signal.aborted && requestedRevision === revision.current) setError(`${format === 'pdf' ? '검증 보고서 PDF' : '검증 데이터 JSON'} 다운로드 실패: ${reason.message}`)
    } finally {
      if (reportRequest.current === controller) reportRequest.current = null
      if (!controller.signal.aborted && requestedRevision === revision.current) setDownloading('')
    }
  }

  return <section className="panel compare-panel">
    <div className="panel-heading"><div><span className="eyebrow">BEFORE · AFTER</span><h2>검사 전후 비교</h2><small>같은 대상과 같은 검사 범위의 이전 결과·이후 결과를 비교합니다. 미검출은 자동 조치 완료 판정이 아닙니다.</small></div></div>
    <div className="compare-controls">
      <label>이전 검사<select value={baseId} onChange={(event) => { resetResult(); setBaseId(event.target.value); setTargetId('') }}><option value="">이전 검사 선택</option>{analyses.filter((run) => run.asset_id != null && run.scan_scope).map((run) => <option key={run.id} value={run.id}>{label(run)}</option>)}</select></label>
      <label>이후 검사<select value={targetId} disabled={!base || !candidates.length} onChange={(event) => { resetResult(); setTargetId(event.target.value) }}><option value="">{base && !candidates.length ? '같은 대상·범위의 이후 검사가 없습니다' : '이후 검사 선택'}</option>{candidates.map((run) => <option key={run.id} value={run.id}>{label(run)}</option>)}</select></label>
      <button className="primary" disabled={!target || busy} onClick={compare}>{busy ? '비교 중…' : '검사 전후 비교'}</button>
    </div>
    {error && <p className="form-error compare-panel" role="alert">{error}</p>}
    {result && <>
      <p className="subtle compare-panel">검사 #{result.base.id} ({new Date(result.base.imported_at).toLocaleString('ko-KR')}) → 검사 #{result.target.id} ({new Date(result.target.imported_at).toLocaleString('ko-KR')}) · {result.target.asset_tag} · {analysisScopeText[result.target.scan_scope] || scopeLabel(result.target.scan_scope)}</p>
      <div className="panel-heading compare-panel"><small>검사 범위·도구·원본 식별정보·CVE 전후 결과를 포함합니다.</small><div className="action-row"><button className="table-button" aria-label="검증 보고서 PDF" disabled={Boolean(downloading)} onClick={() => downloadReport('pdf')}>{downloading === 'pdf' ? 'PDF 다운로드 중…' : '검증 보고서 PDF'}</button><button className="table-button" aria-label="검증 데이터 JSON" disabled={Boolean(downloading)} onClick={() => downloadReport('json')}>{downloading === 'json' ? 'JSON 다운로드 중…' : '검증 데이터 JSON'}</button></div></div>
      {!!result.warnings?.length && <ul className="inline-result" aria-label="검사 비교 주의사항">{result.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul>}
      {!result.comparable && <p className="inline-result" role="status">검사 조건 차이를 함께 확인하세요. 아래는 원본 보고서의 탐지 변화입니다.</p>}
        <div className="diff-grid">{[['persistent', '계속 검출'], ['new', '새로 검출'], ['no_longer_detected', '재검사 미검출'], ['component_removed', '구성요소 제거']].map(([key, title]) => <article key={key}><b>{title}</b><strong>{result.summary[key]}건</strong></article>)}</div>
        <div className="table-wrap compare-panel"><table aria-label="검사 전후 CVE 비교"><thead><tr><th>CVE</th><th>구성요소</th><th>이전 버전</th><th>이후 버전</th><th>수정 버전</th><th>심각도</th><th>재검사 결과</th></tr></thead><tbody>
          {findings.slice(currentPage * pageSize, (currentPage + 1) * pageSize).map((finding, index) => <tr key={`${finding.cve_id}-${finding.component_name}-${index}`}><td><code>{finding.cve_id}</code></td><td><strong>{finding.component_name}</strong></td><td>{finding.before_versions?.join(', ') || '버전 정보 없음'}</td><td>{finding.after_versions?.join(', ') || '버전 정보 없음'}</td><td>{finding.fixed_versions?.join(', ') || '확인 필요'}</td><td><span className={`severity severity-${(finding.severity || 'UNKNOWN').toLowerCase()}`}>{finding.severity || 'UNKNOWN'}</span></td><td><span className={`job${finding.status === 'NEW' ? ' job-failed' : finding.status === 'PERSISTENT' ? ' job-running' : ''}`}>{comparisonStatusText[finding.status] || finding.status}</span></td></tr>)}
          {!findings.length && <tr><td colSpan="7" className="empty">비교할 CVE 탐지 결과가 없습니다.</td></tr>}
        </tbody></table></div>
        {!!findings.length && <div className="panel-heading compare-panel"><span className="subtle">비교 결과 총 {findings.length}건 · {currentPage * pageSize + 1}–{Math.min((currentPage + 1) * pageSize, findings.length)}건 표시</span><div className="action-row"><button className="table-button" aria-label="비교 이전 페이지" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>이전</button><span className="subtle">{currentPage + 1} / {pageCount} 페이지</span><button className="table-button" aria-label="비교 다음 페이지" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>다음</button></div></div>}
    </>}
  </section>
}

function Security({ analyses, sboms, users, onChanged, canEdit, sbomId, onSelectSbom, onViewSbom, onViewHistory }) {
  const [busy, setBusy] = useState(false)
  const [page, setPage] = useState({ sbomId, number: 0 })
  const [cveRevision, setCveRevision] = useState(0)
  const [cveRead, setCveRead] = useState(null)
  const [selectedFinding, setSelectedFinding] = useState(null)
  const scanRequest = useRef(null)
  const pageSize = 100
  const currentPage = page.sbomId === sbomId ? page.number : 0
  const cveKey = `${sbomId}:${currentPage}:${cveRevision}`
  const currentRead = cveRead?.key === cveKey ? cveRead : null
  const cveLoading = Boolean(sbomId && (!currentRead || currentRead.status === 'loading'))
  const cveError = currentRead?.error || ''
  const cveTotal = currentRead?.data?.total || 0
  const pageCount = Math.max(1, Math.ceil(cveTotal / pageSize))
  const visibleVulnerabilities = currentRead?.data?.items || []
  const refreshCves = () => setCveRevision((revision) => revision + 1)

  useEffect(() => {
    if (!sbomId) return
    const controller = new AbortController()
    setCveRead({ key: cveKey, status: 'loading' })
    const params = new URLSearchParams({ sbom_id: String(sbomId), status: 'ALL', limit: String(pageSize), offset: String(currentPage * pageSize) })
    api(`/vulnerability-work?${params}`, { signal: controller.signal }).then((result) => {
      if (controller.signal.aborted) return
      if (currentPage && currentPage * pageSize >= result.total) {
        setPage({ sbomId, number: Math.max(0, Math.ceil(result.total / pageSize) - 1) })
        return
      }
      setCveRead({ key: cveKey, status: 'success', data: result })
    }).catch((reason) => {
      if (!controller.signal.aborted) setCveRead({ key: cveKey, status: 'error', error: reason.message })
    })
    return () => controller.abort()
  }, [sbomId, currentPage, cveKey])

  useEffect(() => {
    setBusy(false)
    return () => { scanRequest.current?.abort(); scanRequest.current = null }
  }, [sbomId])

  function selectSbom(value) {
    onSelectSbom(value); setPage({ sbomId: value, number: 0 }); setSelectedFinding(null)
  }
  useEffect(() => { setSelectedFinding(null) }, [sbomId, currentPage])

  async function scan() {
    if (!canEdit || !sbomId || scanRequest.current) return
    const controller = new AbortController()
    scanRequest.current = controller
    setBusy(true)
    try {
      const result = await api(`/vulnerabilities/scan/sbom/${sbomId}`, { method: 'POST', signal: controller.signal })
      if (controller.signal.aborted) return
      setSelectedFinding(null); refreshCves()
      await onChanged(`OSV 조회 완료: ${result.unique_vulnerabilities}건 · CVE 외 ${result.ignored_non_cve}건 · 버전 미확인 ${result.skipped_components || 0}건 · 철회 ${result.ignored_withdrawn || 0}건 · 영향 구간 외 ${result.ignored_unaffected || 0}건 제외`, false, controller.signal)
    } catch (reason) { if (!controller.signal.aborted) onChanged(reason.message, true, controller.signal) }
    finally { if (!controller.signal.aborted) { scanRequest.current = null; setBusy(false) } }
  }
  async function downloadBundle(run) {
    try { await download(`/analyses/${run.id}/bundle`, `eolwatch-analysis-${run.id}.json`) }
    catch (reason) { onChanged(reason.message, true) }
  }

  return <>
    <section className="panel full-panel compare-panel">
      <div className="panel-heading"><div><span className="eyebrow">RECENT SCANS</span><h2>최근 검사 결과</h2></div><span className="subtle">최근 {analyses.length}건</span><button className="secondary" onClick={onViewHistory}>전체 검사 이력 검색</button></div>
      <div className="table-wrap"><table aria-label="최근 검사 결과"><thead><tr><th>등록 시각</th><th>대상·범위</th><th>검사 도구</th><th>결과</th><th>확인</th></tr></thead>
        <tbody>{analyses.map((run) => <tr key={run.id}>
          <td>{new Date(run.imported_at).toLocaleString('ko-KR')}<small>검사 #{run.id} · SBOM #{run.sbom_id}</small></td>
          <td><strong>{run.asset_tag} · {run.asset_name}</strong><small>{analysisScopeText[run.scan_scope] || scopeLabel(run.scan_scope)}</small></td>
          <td><strong>{run.scanner} {run.scanner_version}</strong><small>SBOM 생성: {run.generator || '미상'}</small>{(run.database_info?.built || run.database_info?.status?.built) && <small>DB 기준: {new Date(run.database_info.built || run.database_info.status.built).toLocaleString('ko-KR')}</small>}</td>
          <td><strong>CVE {run.cve_count}개 · 구성요소 연결 {run.link_count}건</strong><small>구성요소 {run.component_count}개 · 전체 탐지 {run.match_count}건 · CVE 외 {run.ignored_non_cve}건</small></td>
          <td><div className="action-row"><button className="table-button" aria-label={`검사 ${run.id} CVE 보기`} onClick={() => selectSbom(String(run.sbom_id))}>CVE 보기</button><button className="table-button" aria-label={`검사 ${run.id} 원본 다운로드`} onClick={() => downloadBundle(run)}>원본 JSON</button></div></td>
        </tr>)}{!analyses.length && <tr><td colSpan="5" className="empty">저장된 검사 결과가 없습니다.</td></tr>}</tbody>
      </table></div>
    </section>
    <AnalysisComparison analyses={analyses} />
    <section className="panel full-panel compare-panel">
    <div className="panel-heading">
      <div><span className="eyebrow">CVE · VEX</span><h2>CVE 조치 현황</h2><small>선택한 SBOM의 Grype 검사 및 OSV 조회 결과 중 CVE 식별자가 있는 항목을 표시합니다. 조치 상태는 담당자가 근거를 확인한 뒤 수동으로 기록합니다.</small></div>
      <div className="action-row"><label>확인할 SBOM<select value={sbomId} onChange={(event) => selectSbom(event.target.value)}><option value="">SBOM 선택</option>{sboms.map((item) => <option value={item.id} key={item.id}>#{item.id} · {analyses.find((run) => run.sbom_id === item.id)?.asset_tag || 'SBOM'} · 구성요소 {item.component_count}</option>)}</select></label>{canEdit && <button className="primary" disabled={!sbomId || busy} onClick={scan}>{busy ? '조회 중…' : 'OSV 조회'}</button>}</div>
    </div>
    {sbomId && <button className="secondary" onClick={() => onViewSbom(Number(sbomId))}>선택한 SBOM의 의존성 목록 보기</button>}
    {selectedFinding && <VulnerabilityActions key={selectedFinding.link_id} finding={selectedFinding} analyses={analyses} users={users} canEdit={canEdit} request={api} onSaved={() => { setSelectedFinding(null); refreshCves(); return onChanged('조치 내용과 이력을 저장했습니다.') }} onClose={() => setSelectedFinding(null)} />}
    {cveLoading && <p role="status">CVE 결과를 불러오는 중…</p>}
    {cveError && <div role="alert"><p className="form-error">CVE 결과 조회 실패: {cveError}</p><button className="secondary" type="button" onClick={refreshCves}>CVE 조회 다시 시도</button></div>}
    <div className="table-wrap"><table aria-label="선택한 SBOM의 CVE"><thead><tr><th>CVE·출처</th><th>영향 대상</th><th>구성요소</th><th>수정 버전</th><th>심각도</th><th>조치 상태</th></tr></thead>
      <tbody>{visibleVulnerabilities.map((item) => <tr key={item.link_id}><td><code>{item.cve_id}</code><small>{item.finding_source || item.source || '출처 미상'}{item.analysis_run_id ? ` · 검사 #${item.analysis_run_id}` : ''}</small><small>{item.summary || '설명 없음'}</small></td><td><strong>{item.asset_tag || '미연결'}</strong><small>{item.asset_name || 'SBOM에 대상을 연결하세요'}</small></td><td><strong>{item.component_name}</strong><small>검사 당시 {item.component_version || '버전 미상'}</small></td><td><strong>{item.fixed_versions?.length ? item.fixed_versions.join(', ') : item.fixed_version || '확인 필요'}</strong></td><td><span className={`severity severity-${item.severity.toLowerCase()}`}>{item.severity}</span></td><td><span aria-label={`${item.cve_id} ${item.component_name} 조치 상태`}>{vexStatusText[item.vex_status] || item.vex_status}</span><small>담당 {item.assignee_username || '미지정'}</small>{item.due_date && <small>기한 {item.due_date}</small>}<button className="table-button" aria-label={`${item.cve_id} ${item.component_name} ${canEdit ? '조치 관리' : '조치 이력'}`} onClick={() => setSelectedFinding(item)}>{canEdit ? '조치 관리' : '조치 이력'}</button></td></tr>)}{!cveLoading && !cveError && !visibleVulnerabilities.length && <tr><td colSpan="6" className="empty">{sbomId ? '이 SBOM에 저장된 CVE 결과가 없습니다.' : '최근 검사 결과에서 CVE 보기를 누르거나 SBOM을 선택하세요.'}</td></tr>}</tbody>
    </table></div>
    {!cveLoading && !cveError && cveTotal > 0 && <div className="panel-heading">
      <span className="subtle">총 {cveTotal}건 · {currentPage * pageSize + 1}–{Math.min(currentPage * pageSize + visibleVulnerabilities.length, cveTotal)}건 표시</span>
      <div className="action-row"><button className="table-button" disabled={currentPage === 0} onClick={() => setPage({ sbomId, number: currentPage - 1 })}>이전 페이지</button><span className="subtle">{currentPage + 1} / {pageCount} 페이지</span><button className="table-button" disabled={currentPage + 1 >= pageCount} onClick={() => setPage({ sbomId, number: currentPage + 1 })}>다음 페이지</button></div>
    </div>}
  </section>
  </>
}

function Admin({ auditLogs, users, onChanged, canEdit }) {
  async function createUser(event) {
    const form = event.currentTarget
    event.preventDefault()
    try {
      const data = Object.fromEntries(new FormData(form))
      await api('/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      form.reset(); onChanged('사용자 계정을 만들었습니다.')
    } catch (reason) { onChanged(reason.message, true) }
  }
  if (!canEdit) return <section className="panel full-panel"><p className="empty">사용자 관리와 감사 로그는 관리자만 볼 수 있습니다.</p></section>
  return <>
    <section className="split-grid operations-section">
      <article className="panel"><span className="eyebrow">ACCESS CONTROL</span><h2>사용자 관리</h2><form className="vertical-form" onSubmit={createUser}><label>아이디<input name="username" minLength="3" required /></label><label>초기 비밀번호<input name="password" type="password" minLength="10" required /></label><label>권한<select name="role"><option value="VIEWER">조회자</option><option value="ADMIN">관리자</option></select></label><button className="primary">계정 생성</button></form><div className="simple-list">{users.map((item) => <div key={item.id}><strong>{item.username}</strong><small>{item.role} · {item.active ? '사용 중' : '비활성'}</small></div>)}</div></article>
      <article className="panel"><span className="eyebrow">ROLES</span><h2>권한 안내</h2><p className="workspace-help">관리자는 서버 등록·검사 실행·조치 기록을 할 수 있고, 조회자는 검사 결과와 기록만 볼 수 있습니다. 모든 변경 요청은 감사 로그에 남습니다.</p></article>
    </section>
    <section className="panel full-panel audit-panel"><div className="panel-heading"><div><span className="eyebrow">AUDIT</span><h2>변경 감사 로그</h2></div><span className="subtle">최근 {auditLogs.length}건</span></div><div className="table-wrap"><table><thead><tr><th>시각</th><th>사용자</th><th>방식</th><th>경로</th><th>결과</th></tr></thead><tbody>{auditLogs.map((item) => <tr key={item.id}><td>{new Date(item.created_at).toLocaleString('ko-KR')}</td><td>{item.username}</td><td><code>{item.method}</code></td><td>{item.path}</td><td>{item.status_code}</td></tr>)}</tbody></table></div></section>
  </>
}

export default function App() {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('eolwatch_user')) }
    catch { return null }
  })
  const [tab, setTab] = useState('overview')
  const [historyView, setHistoryView] = useState('projects')
  const [summary, setSummary] = useState(EMPTY_SUMMARY)
  const [assets, setAssets] = useState([])
  const [sboms, setSboms] = useState([])
  const [checks, setChecks] = useState([])
  const [analyses, setAnalyses] = useState([])
  const [analysisJobs, setAnalysisJobs] = useState([])
  const [jobsError, setJobsError] = useState('')
  const [pendingAssets, setPendingAssets] = useState([])
  const [selectedSbomId, setSelectedSbomId] = useState('')
  const requestedJobs = useRef(new Set())
  const requestingAssets = useRef(new Set())
  const jobRequests = useRef(new Set())
  const comparisonRequest = useRef(null)
  const jobsRevision = useRef(0)
  const messageTimer = useRef(null)
  const [auditLogs, setAuditLogs] = useState([])
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [focusedAssetId, setFocusedAssetId] = useState(null)
  const [projectContext, setProjectContext] = useState({})
  const [analysisInput, setAnalysisInput] = useState({})
  const [explorerSbomId, setExplorerSbomId] = useState(null)
  const [comparison, setComparison] = useState(null)
  const [workQuery, setWorkQuery] = useState(null)

  const canEdit = user?.role === 'ADMIN'
  const logout = useCallback(() => {
    localStorage.removeItem('eolwatch_token'); localStorage.removeItem('eolwatch_user'); setUser(null)
  }, [])
  const load = useCallback(async (message = '', isError = false, signal) => {
    try {
      const [nextSummary, nextAssets, nextSboms, nextChecks, nextAnalyses, nextAuditLogs, nextUsers] = await Promise.all([
        ...['/dashboard/summary', '/assets', '/sboms', '/checks', '/analyses'].map((path) => api(path, { signal })),
        canEdit ? api('/auth/audit-logs', { signal }) : Promise.resolve([]), canEdit ? api('/auth/users', { signal }) : Promise.resolve([]),
      ])
      if (signal?.aborted) return false
      setSummary(nextSummary); setAssets(nextAssets); setSboms(nextSboms); setChecks(nextChecks); setAnalyses(nextAnalyses); setAuditLogs(nextAuditLogs); setUsers(nextUsers)
      setError(isError ? message : ''); setMessage(isError ? '' : message)
      clearTimeout(messageTimer.current)
      if (message) messageTimer.current = setTimeout(() => setMessage(''), 2500)
      return true
    } catch (reason) {
      if (signal?.aborted) return false
      if (reason.message.includes('로그인') || reason.message.includes('토큰')) logout()
      else setError(`API 연결 실패: ${reason.message}`)
      return false
    }
    finally { if (!signal?.aborted) setLoading(false) }
  }, [canEdit, logout])

  function openHistory(view) { setHistoryView(view); setTab('history') }

  function acceptedAnalysisJob(job) {
    jobsRevision.current += 1
    requestedJobs.current.add(job.id)
    setAnalysisJobs((current) => [job, ...current.filter((item) => item.id !== job.id)])
    setTab(isZipScope(job.scan_scope) ? 'dev' : 'infra')
    setMessage('검사 요청을 저장했습니다. 작업 진행 상태를 확인하세요.')
  }

  function viewProjects(assetId = null) {
    setProjectContext({ assetId }); openHistory('projects')
  }

  function viewSbom(sbomId) {
    setExplorerSbomId(sbomId); openHistory('sbom')
  }

  function viewAssetWork(assetId) {
    setWorkQuery({ filters: { q: '', asset_id: String(assetId), status: 'OPEN', severity: '', assignee_id: '', unassigned: false, overdue: false }, offset: 0, limit: 25, revision: 0 })
    openHistory('work')
  }

  async function viewComparison(baseId, targetId, signal) {
    if (comparisonRequest.current || signal?.aborted) return
    const controller = new AbortController(); jobRequests.current.add(controller)
    comparisonRequest.current = controller
    const abort = () => controller.abort()
    signal?.addEventListener('abort', abort, { once: true })
    try {
      const runs = await Promise.all([baseId, targetId].map((id) => api(`/analyses/runs/${id}`, { signal: controller.signal })))
      if (!controller.signal.aborted) { setComparison({ runs, baseId, targetId }); openHistory('comparison') }
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally { jobRequests.current.delete(controller); signal?.removeEventListener('abort', abort); if (comparisonRequest.current === controller) comparisonRequest.current = null }
  }

  useEffect(() => () => { comparisonRequest.current?.abort(); comparisonRequest.current = null }, [tab, historyView, projectContext.assetId, projectContext.scanScope, user?.id])

  async function cancelAnalysis(job) {
    if (!canEdit || requestingAssets.current.has(job.asset_id)) return
    const controller = new AbortController(); jobRequests.current.add(controller)
    requestingAssets.current.add(job.asset_id); setPendingAssets([...requestingAssets.current]); jobsRevision.current += 1
    try {
      const updated = await api(`/analyses/jobs/${job.id}/cancel`, { method: 'POST', signal: controller.signal })
      if (!controller.signal.aborted) {
        jobsRevision.current += 1
        setAnalysisJobs((current) => current.map((item) => item.id === updated.id ? updated : item))
        setMessage(updated.status === 'CANCELLED' ? '대기 중인 검사를 취소했습니다.' : '취소를 요청했습니다. 프로세스 종료를 확인할 때까지 기다려 주세요.')
      }
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally {
      jobRequests.current.delete(controller); requestingAssets.current.delete(job.asset_id)
      if (!controller.signal.aborted) setPendingAssets([...requestingAssets.current])
    }
  }

  async function requestAnalysis(assetId, retryJobId, scanScope = 'ubuntu-dpkg-installed') {
    if (!canEdit || requestingAssets.current.has(assetId)) return
    const current = analysisJobs.find((job) => job.asset_id === assetId && activeAnalysisJob(job))
    if (current) { requestedJobs.current.add(current.id); setTab(isZipScope(current.scan_scope) ? 'dev' : 'infra'); return }
    const controller = new AbortController()
    jobRequests.current.add(controller)
    requestingAssets.current.add(assetId); setPendingAssets([...requestingAssets.current])
    jobsRevision.current += 1
    setError('')
    try {
      const options = { method: 'POST', signal: controller.signal }
      if (!retryJobId) { options.headers = { 'Content-Type': 'application/json' }; options.body = JSON.stringify({ scan_scope: scanScope }) }
      const job = await api(retryJobId ? `/analyses/jobs/${retryJobId}/retry` : `/analyses/assets/${assetId}/jobs`, options)
      if (controller.signal.aborted) return
      jobsRevision.current += 1
      requestedJobs.current.add(job.id)
      setAnalysisJobs((previous) => [job, ...previous.filter((item) => item.id !== job.id)])
      setJobsError(''); setTab(isZipScope(job.scan_scope) ? 'dev' : 'infra')
    } catch (reason) {
      if (!controller.signal.aborted) setError(`검사 요청 실패: ${reason.message}`)
    } finally {
      jobRequests.current.delete(controller)
      if (!controller.signal.aborted) {
        requestingAssets.current.delete(assetId); setPendingAssets([...requestingAssets.current])
      }
    }
  }

  async function viewAnalysisResult(sbomId) {
    const controller = new AbortController()
    jobRequests.current.add(controller)
    try {
      if (!sboms.some((sbom) => sbom.id === sbomId) && !await load('', false, controller.signal)) return
      if (!controller.signal.aborted) { setSelectedSbomId(String(sbomId)); openHistory('cve') }
    } finally { jobRequests.current.delete(controller) }
  }

  useEffect(() => {
    if (!user) return
    const controller = new AbortController()
    setLoading(true); load('', false, controller.signal)
    return () => { controller.abort(); clearTimeout(messageTimer.current) }
  }, [user?.id, user?.role, load])

  useEffect(() => {
    if (!user) return
    const controller = new AbortController()
    let timer
    let observedSuccesses
    const tracking = new Set()
    setAnalysisJobs([]); setJobsError(''); setPendingAssets([]); setSelectedSbomId('')
    async function pollJobs() {
      const revision = jobsRevision.current
      try {
        const [recent, active] = await Promise.all(['/analyses/jobs', '/analyses/jobs/active'].map((path) => api(path, { signal: controller.signal })))
        const merged = new Map([...recent, ...active].map((job) => [job.id, job]))
        for (const job of active) tracking.add(job.id)
        for (const id of requestedJobs.current) tracking.add(id)
        const missing = [...tracking].filter((id) => !merged.has(id))
        const tracked = await Promise.all(missing.map((id) => api(`/analyses/jobs/${id}`, { signal: controller.signal }).catch((reason) => {
          if (reason.status === 404) { tracking.delete(id); requestedJobs.current.delete(id); return null }
          throw reason
        })))
        for (const job of tracked) if (job) merged.set(job.id, job)
        const jobs = [...merged.values()].sort((left, right) => right.id - left.id)
        for (const job of jobs) if (!activeAnalysisJob(job)) tracking.delete(job.id)
        if (controller.signal.aborted || revision !== jobsRevision.current) return
        setAnalysisJobs(jobs); setJobsError('')
        if (!observedSuccesses) observedSuccesses = new Set(jobs.filter((job) => job.status === 'SUCCESS').map((job) => job.id))
        const newSuccesses = jobs.filter((job) => job.status === 'SUCCESS' && !observedSuccesses.has(job.id))
        const completed = jobs.filter((job) => requestedJobs.current.has(job.id) && job.status === 'SUCCESS' && job.sbom_id)
        jobs.filter((job) => ['FAILED', 'CANCELLED'].includes(job.status)).forEach((job) => requestedJobs.current.delete(job.id))
        if (completed.length) {
          const loaded = await load('검사가 완료되었습니다. 새 SBOM의 CVE 결과를 확인하세요.', false, controller.signal)
          if (loaded && !controller.signal.aborted) {
            completed.forEach((job) => requestedJobs.current.delete(job.id))
            newSuccesses.forEach((job) => observedSuccesses.add(job.id))
            setSelectedSbomId(String(completed[0].sbom_id)); openHistory('cve')
          }
        } else if (newSuccesses.length) {
          const nextSummary = await api('/dashboard/summary', { signal: controller.signal })
          if (!controller.signal.aborted) {
            setSummary(nextSummary); newSuccesses.forEach((job) => observedSuccesses.add(job.id))
          }
        }
      } catch (reason) {
        if (!controller.signal.aborted) setJobsError(`검사 상태를 갱신하지 못했습니다: ${reason.message} 잠시 후 다시 확인합니다.`)
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(pollJobs, 3000)
      }
    }
    pollJobs()
    return () => {
      controller.abort(); clearTimeout(timer)
      jobRequests.current.forEach((request) => request.abort()); jobRequests.current.clear()
      requestingAssets.current.clear(); requestedJobs.current.clear()
    }
  }, [user?.id, user?.role, load])

  if (!user) return <Login onLogin={setUser} />

  const zipJobs = analysisJobs.filter((job) => isZipScope(job.scan_scope))
  const serverJobs = analysisJobs.filter((job) => !isZipScope(job.scan_scope))
  const jobsProps = { error: jobsError, pendingAssets, onRetry: (job) => requestAnalysis(job.asset_id, job.id), onCancel: cancelAnalysis, onViewResult: viewAnalysisResult, canEdit }
  const historyViews = [['projects', historyTitles.projects], ['cve', historyTitles.cve], ['work', historyTitles.work], ...(explorerSbomId ? [['sbom', historyTitles.sbom]] : []), ...(comparison ? [['comparison', historyTitles.comparison]] : [])]

  return (
    <div className="app-shell">
      <aside>
        <div className="brand"><span className="brand-mark">E</span><div><strong>EOLWatch</strong><small>Dev &amp; Infra Vulnerability Scan</small></div></div>
        <nav>
          <button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}><span>⌁</span> 개요</button>
          <button className={tab === 'dev' ? 'active' : ''} onClick={() => setTab('dev')}><span>▷</span> 개발 검사</button>
          <button className={tab === 'infra' ? 'active' : ''} onClick={() => setTab('infra')}><span>□</span> 인프라 검사</button>
          <button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}><span>▤</span> 검사 기록</button>
          <button className={tab === 'admin' ? 'active' : ''} onClick={() => setTab('admin')}><span>≡</span> 관리</button>
        </nav>
        <div className="standard-note"><b>{user.username}</b><p>{canEdit ? '관리자' : '조회자'} 권한으로 접속했습니다.</p><button className="logout" onClick={logout}>로그아웃</button></div>
      </aside>
      <main>
        <header><div><span className="eyebrow">DEV &amp; INFRA VULNERABILITY SCAN</span><h1>{tab === 'history' ? `검사 기록 · ${historyTitles[historyView]}` : tabTitles[tab]}</h1></div><div className="today"><small>기준일</small><strong>{new Intl.DateTimeFormat('ko-KR', { dateStyle: 'long' }).format(new Date())}</strong></div></header>
        {error && <div className="alert error">{error}</div>}
        {message && <div className="alert success">{message}</div>}
        {tab === 'history' && <div className="analysis-input-tabs" role="tablist" aria-label="검사 기록 종류">{historyViews.map(([value, label]) => <button key={value} className="secondary" role="tab" aria-selected={historyView === value} aria-pressed={historyView === value} onClick={() => setHistoryView(value)}>{label}</button>)}</div>}
        {loading ? <div className="loading">데이터를 불러오는 중입니다…</div>
          : tab === 'overview' ? <Overview summary={summary} onViewResult={viewAnalysisResult} analysisJobs={analysisJobs} />
          : tab === 'dev' ? <><AnalysisTargets mode="zip" assets={assets} canEdit={canEdit} request={api} onJobQueued={acceptedAnalysisJob} initialAssetId={analysisInput.assetId} initialProjectName={analysisInput.projectName} initialScope={analysisInput.scanScope} initialTargetPath={analysisInput.targetPath} /><AnalysisJobs jobs={zipJobs} title="소스 ZIP 검사 작업" hint="업로드한 ZIP에서 의존성 목록을 뽑고 취약점 DB와 대조합니다. 완료되면 결과를 확인할 수 있습니다." {...jobsProps} /></>
          : tab === 'infra' ? <><Servers assets={assets} onChanged={load} canEdit={canEdit} analysisJobs={analysisJobs} pendingAssets={pendingAssets} onStartAnalysis={requestAnalysis} focusedAssetId={focusedAssetId} onViewProjects={viewProjects} onViewCve={viewAssetWork} onViewSbom={viewSbom} /><AnalysisJobs jobs={serverJobs} title="서버 검사 작업" hint="검사 도구를 서버에 복사해 실행하고 설치 패키지를 수집한 뒤 취약점을 검사합니다." {...jobsProps} /><AnalysisTargets mode="ssh" assets={assets} canEdit={canEdit} request={api} onJobQueued={acceptedAnalysisJob} initialAssetId={analysisInput.assetId} initialProjectName={analysisInput.projectName} initialScope={analysisInput.scanScope} initialTargetPath={analysisInput.targetPath} /><Checks checks={checks} /></>
          : tab === 'history' ? (
            historyView === 'projects' ? <ProjectHub assets={assets} canEdit={canEdit} request={api} download={download} onChanged={load} onJobQueued={acceptedAnalysisJob} onViewResult={viewAnalysisResult} onViewSbom={viewSbom} onCompare={viewComparison} onNewAnalysis={(input) => { setAnalysisInput(input); setTab(input.scanScope && !isZipScope(input.scanScope) ? 'infra' : 'dev') }} initialAssetId={projectContext.assetId} initialScope={projectContext.scanScope} onSelectionChange={setProjectContext} onViewWork={viewAssetWork} />
            : historyView === 'cve' ? <Security analyses={analyses} sboms={sboms} users={users} onChanged={load} canEdit={canEdit} sbomId={selectedSbomId} onSelectSbom={setSelectedSbomId} onViewSbom={viewSbom} onViewHistory={() => viewProjects()} />
            : historyView === 'work' ? <VulnerabilityWorklist assets={assets} users={users} analyses={analyses} canEdit={canEdit} request={api} onChanged={load} onViewResult={viewAnalysisResult} initialQuery={workQuery} onQueryChange={setWorkQuery} />
            : historyView === 'comparison' && comparison ? <><button className="secondary" onClick={() => setHistoryView('projects')}>검사 이력으로 돌아가기</button><AnalysisComparison key={`${comparison.baseId}-${comparison.targetId}`} analyses={comparison.runs} initialBaseId={comparison.baseId} initialTargetId={comparison.targetId} /></>
            : explorerSbomId ? <SbomExplorer key={explorerSbomId} sbomId={explorerSbomId} request={api} download={download} canEdit={canEdit} onChanged={load} onClose={() => { setExplorerSbomId(null); setHistoryView('projects') }} onViewCve={viewAnalysisResult} />
            : <p className="empty">검사 이력에서 결과를 선택하세요.</p>
          )
          : <Admin auditLogs={auditLogs} users={users} onChanged={load} canEdit={canEdit} />}
      </main>
    </div>
  )
}
