import { useEffect, useRef, useState } from 'react'
import './Workspace.css'

const profiles = { 'ssh-project-directory': '서버 프로젝트 폴더', 'ssh-python-environment': '서버 Python 가상환경', 'ubuntu-dpkg-installed': 'Ubuntu 설치 패키지', 'demo-python-venv': '기존 Python 데모 앱' }
const dateTime = (value) => value ? new Date(value).toLocaleString('ko-KR') : '미기록'
export function scopeLabel(scope = '') {
  if (scope.startsWith('source-zip:')) return `소스 ZIP · ${scope.slice('source-zip:'.length)}`
  for (const [profile, name] of Object.entries(profiles)) if (scope.startsWith(`${profile}:`)) return `${name} · ${scope.slice(profile.length + 1)}`
  return profiles[scope] || scope
}
export function isExecutableScope(scope = '') {
  if (scope.startsWith('source-zip:')) return !!scope.slice('source-zip:'.length).trim()
  const profile = scope.split(':')[0]
  return Object.hasOwn(profiles, profile) && (!scope.includes(':') || profile.startsWith('ssh-'))
}

export default function AnalysisTargets({ assets, canEdit, request, onJobQueued, initialAssetId, initialScope, initialProjectName, initialTargetPath }) {
  const [mode, setMode] = useState('zip')
  const [assetId, setAssetId] = useState('')
  const [project, setProject] = useState('')
  const [file, setFile] = useState(null)
  const [profile, setProfile] = useState('ssh-project-directory')
  const [path, setPath] = useState('')
  const [interval, setInterval] = useState('1440')
  const [schedules, setSchedules] = useState([])
  const [scheduleEdits, setScheduleEdits] = useState({})
  const [busy, setBusy] = useState('')
  const [patching, setPatching] = useState(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [scheduleError, setScheduleError] = useState('')
  const [scheduleBusy, setScheduleBusy] = useState(false)
  const operation = useRef(null)
  const scheduleRequest = useRef(null)
  const updateRequest = useRef(null)
  const fileInput = useRef(null)
  const pathRequired = profile.startsWith('ssh-')
  const asset = assets.find((item) => String(item.id) === assetId)
  const sshReady = asset?.monitored && asset.ip_address && asset.ssh_username

  useEffect(() => {
    operation.current?.abort(); operation.current = null; setBusy(''); setError('')
    setAssetId(initialAssetId == null ? '' : String(initialAssetId))
    setFile(null); if (fileInput.current) fileInput.current.value = ''
    if (initialScope && isExecutableScope(initialScope) && !initialScope.startsWith('source-zip:')) {
      const separator = initialScope.indexOf(':')
      setMode('ssh'); setProfile(separator < 0 ? initialScope : initialScope.slice(0, separator))
      setPath(initialTargetPath || (separator < 0 ? '' : initialScope.slice(separator + 1)))
    } else {
      setMode('zip'); setProject(initialScope && !isExecutableScope(initialScope) ? '' : initialProjectName || initialScope?.slice('source-zip:'.length) || '')
    }
  }, [initialAssetId, initialScope, initialProjectName, initialTargetPath])

  async function loadSchedules() {
    const controller = new AbortController(); scheduleRequest.current?.abort(); scheduleRequest.current = controller
    setScheduleBusy(true); setScheduleError('')
    try { const values = await request('/analyses/schedules', { signal: controller.signal }); if (!controller.signal.aborted) setSchedules(values) }
    catch (reason) { if (!controller.signal.aborted) setScheduleError(reason.message) }
    finally { if (!controller.signal.aborted) setScheduleBusy(false) }
  }
  useEffect(() => { loadSchedules(); return () => { operation.current?.abort(); scheduleRequest.current?.abort(); updateRequest.current?.abort() } }, [])

  async function submit(event, scheduled = false) {
    event.preventDefault()
    if (!canEdit || operation.current || !assetId) return
    const form = event.currentTarget.tagName === 'FORM' ? event.currentTarget : event.currentTarget.form
    if (!form?.reportValidity()) return
    if (mode === 'zip' && (!file || !project.trim())) return
    if (mode === 'ssh' && (!sshReady || (pathRequired && !path.startsWith('/')))) { setError('SSH 점검 대상의 IP·계정과 절대 경로를 확인하세요.'); return }
    if (scheduled && (!Number.isInteger(Number(interval)) || Number(interval) < 5 || Number(interval) > 525600)) { setError('예약 주기는 5~525600분의 정수로 입력하세요.'); return }
    const controller = new AbortController(); operation.current = controller; setBusy(scheduled ? 'schedule' : 'analysis'); setError(''); setMessage('')
    try {
      if (mode === 'zip') {
        if (file.size > 50 * 1024 * 1024) throw new Error('ZIP 파일은 50 MiB까지 업로드할 수 있습니다.')
        const data = new FormData(); data.append('file', file); data.append('project_name', project.trim())
        const job = await request(`/analyses/assets/${assetId}/uploads`, { method: 'POST', body: data, signal: controller.signal })
        if (!controller.signal.aborted) { setFile(null); if (fileInput.current) fileInput.current.value = ''; onJobQueued(job) }
      } else {
        const body = { scan_scope: profile, ...(pathRequired ? { target_path: path.trim() } : {}) }
        const result = await request(scheduled ? '/analyses/schedules' : `/analyses/assets/${assetId}/jobs`, { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(scheduled ? { ...body, asset_id: Number(assetId), interval_minutes: Number(interval), enabled: true } : body) })
        if (!controller.signal.aborted) {
          if (scheduled) { setMessage('정기 분석을 등록했습니다. 다음 실행 시각을 확인하세요.'); await loadSchedules() }
          else onJobQueued(result)
        }
      }
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally { if (operation.current === controller) operation.current = null; if (!controller.signal.aborted) setBusy('') }
  }

  async function changeSchedule(item, enabled) {
    if (!canEdit || updateRequest.current) return
    const minutes = Number(scheduleEdits[item.id] ?? item.interval_minutes)
    if (!Number.isInteger(minutes) || minutes < 5 || minutes > 525600) { setScheduleError('예약 주기는 5~525600분의 정수로 입력하세요.'); return }
    const controller = new AbortController(); updateRequest.current = controller; setPatching(item.id); setScheduleError('')
    try {
      const updated = await request(`/analyses/schedules/${item.id}`, { method: 'PATCH', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interval_minutes: minutes, enabled }) })
      if (!controller.signal.aborted) { setSchedules((current) => current.map((value) => value.id === updated.id ? updated : value)); setScheduleEdits((current) => { const next = { ...current }; delete next[item.id]; return next }) }
    } catch (reason) { if (!controller.signal.aborted) setScheduleError(reason.message) }
    finally { if (updateRequest.current === controller) updateRequest.current = null; if (!controller.signal.aborted) setPatching(null) }
  }

  return <>
    <section className="panel workspace-panel" aria-label="프로젝트 분석">
      <span className="eyebrow">PROJECT ANALYSIS</span><h2>프로젝트 분석</h2><p className="workspace-help">프로젝트 소스 ZIP을 올리거나 등록된 서버의 앱 경로를 지정하세요. 분석 결과는 선택한 자산에 연결됩니다.</p>
      {initialScope && !isExecutableScope(initialScope) && <p className="workspace-help">이전 분석의 실행 입력이 기록되지 않아 새 ZIP 입력으로 시작합니다. 서버 앱을 분석하려면 분석 방식과 경로를 새로 지정하세요.</p>}
      {canEdit ? <>
        <div className="analysis-input-tabs"><button className="secondary" disabled={!!busy} aria-pressed={mode === 'zip'} onClick={() => { setMode('zip'); setError('') }}>소스 ZIP 업로드</button><button className="secondary" disabled={!!busy} aria-pressed={mode === 'ssh'} onClick={() => { setMode('ssh'); setError('') }}>서버 앱 경로</button></div>
        <form className="workspace-form" onSubmit={submit}><fieldset disabled={!!busy}><legend>{mode === 'zip' ? '업로드할 프로젝트' : '서버 분석 대상'}</legend>
          <label>분석 결과를 연결할 자산<select required value={assetId} onChange={(event) => setAssetId(event.target.value)}><option value="">자산 선택</option>{assets.map((item) => <option key={item.id} value={item.id}>{item.asset_tag} · {item.name}</option>)}</select></label>
          {mode === 'zip' ? <><label>프로젝트 이름<input required maxLength={80} value={project} onChange={(event) => setProject(event.target.value)} placeholder="예: 주문 API" /></label><label className="workspace-full">프로젝트 소스 ZIP<input ref={fileInput} type="file" required accept=".zip,application/zip" onChange={(event) => setFile(event.target.files?.[0] || null)} /></label><p className="workspace-help workspace-full">최대 50 MiB. 잠금 파일과 패키지 명세가 포함된 소스 ZIP을 선택하세요. 같은 자산·프로젝트 이름으로 다음 버전을 올리면 전후 비교할 수 있습니다. 패키지를 설치하거나 프로그램을 실행하지 않으며, 포함된 메타데이터에서 구성요소를 식별합니다.</p></> : <><label>서버 분석 방식<select value={profile} onChange={(event) => setProfile(event.target.value)}>{Object.entries(profiles).map(([value, name]) => <option key={value} value={value}>{name}</option>)}</select></label>{pathRequired && <label className="workspace-full">서버 앱 절대 경로<input required value={path} onChange={(event) => setPath(event.target.value)} placeholder={profile === 'ssh-python-environment' ? '/opt/my-app/.venv' : '/opt/my-app'} /></label>}{asset && !sshReady && <p className="form-error">선택한 자산의 관리 IP·SSH 계정·점검 대상 설정이 필요합니다. 작업 대상의 수정 화면에서 설정하세요.</p>}<label>정기 분석 주기 (분)<input type="number" min={5} max={525600} step={1} value={interval} onChange={(event) => setInterval(event.target.value)} /></label><p className="workspace-help">폴더 분석은 잠금 파일·패키지 명세를, Python 가상환경 분석은 설치된 패키지 메타데이터를 읽습니다. SSH 계정이 읽을 수 있는 경로를 지정하세요.</p></>}
          {error && <p className="form-error" role="alert">{error}</p>}<div className="action-row workspace-full"><button className="primary" disabled={!!busy || !assetId || (mode === 'ssh' && !sshReady)}>{busy === 'analysis' ? '분석 요청 중…' : '지금 분석 시작'}</button>{mode === 'ssh' && <button type="button" className="secondary" disabled={!!busy || !sshReady} onClick={(event) => submit(event, true)}>{busy === 'schedule' ? '등록 중…' : '정기 분석 등록'}</button>}</div>
        </fieldset></form>
      </> : <p className="workspace-help">조회 계정은 분석 결과와 예약을 확인할 수 있습니다. 분석 실행·등록은 관리자 권한으로 사용할 수 있습니다.</p>}
      {message && <p className="inline-result" role="status">{message}</p>}
    </section>
    <section className="panel workspace-panel"><div className="workspace-title"><div><span className="eyebrow">SCHEDULED ANALYSIS</span><h2>정기 분석</h2><p className="workspace-help">서버별 주기로 분석을 요청합니다. 실행 중인 분석이 있으면 중복 요청하지 않습니다.</p></div><button className="secondary" disabled={scheduleBusy || patching !== null} onClick={loadSchedules}>예약 새로고침</button></div>
      {scheduleError && <p className="form-error" role="alert">{scheduleError}</p>}
      {scheduleBusy ? <p role="status">예약을 불러오는 중…</p> : <div className="table-wrap"><table aria-label="정기 분석 예약"><thead><tr><th>대상</th><th>상태·다음 실행</th><th>최근 요청</th><th>주기 (분)</th><th>관리</th></tr></thead><tbody>{schedules.map((item) => <tr key={item.id}><td><strong>{item.asset_tag} · {item.asset_name}</strong><small>{scopeLabel(item.scan_scope)}</small></td><td>{item.enabled ? '실행 중' : '일시 중지'}<small>{item.enabled ? dateTime(item.next_run_at) : '예약 중지됨'}</small></td><td>{dateTime(item.last_requested_at)}<small>{item.last_job_id ? `작업 #${item.last_job_id}` : '실행 이력 없음'}</small>{item.last_error && <small>{item.last_error}</small>}</td><td>{canEdit ? <input aria-label={`예약 ${item.id} 주기`} type="number" min={5} max={525600} step={1} disabled={patching !== null} value={scheduleEdits[item.id] ?? item.interval_minutes} onChange={(event) => setScheduleEdits((current) => ({ ...current, [item.id]: event.target.value }))} /> : item.interval_minutes}</td><td>{canEdit && <div className="action-row"><button className="table-button" disabled={patching !== null} onClick={() => changeSchedule(item, item.enabled)}>주기 저장</button><button className="table-button" disabled={patching !== null} onClick={() => changeSchedule(item, !item.enabled)}>{item.enabled ? '일시 중지' : '다시 실행'}</button></div>}</td></tr>)}{!schedules.length && !scheduleError && <tr><td colSpan={5} className="empty">등록된 정기 분석이 없습니다.</td></tr>}</tbody></table></div>}
    </section>
  </>
}
