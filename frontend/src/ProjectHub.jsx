import { useEffect, useRef, useState } from 'react'
import { isExecutableScope, scopeLabel } from './AnalysisTargets'
import './ProjectHub.css'

const PAGE_SIZE = 20
const jobLabels = { QUEUED: '대기', COLLECTING: '수집', SCANNING: '분석', IMPORTING: '저장', SUCCESS: '완료', FAILED: '실패', CANCEL_REQUESTED: '취소 처리 중', CANCELLED: '취소됨' }
const activeStatuses = new Set(['QUEUED', 'COLLECTING', 'SCANNING', 'IMPORTING', 'CANCEL_REQUESTED'])
const cancellableStatuses = new Set(['QUEUED', 'COLLECTING', 'SCANNING', 'IMPORTING'])
const storageLabels = { AVAILABLE: '보관됨', MISSING: '파일 없음', SIZE_MISMATCH: '크기 불일치', UNSAFE_FILE: '파일 접근 불가' }
const dateTime = (value) => value ? new Date(value).toLocaleString('ko-KR') : '기록 없음'
const bytes = (value) => value == null ? '미확인' : Number(value) >= 1024 * 1024 ? `${(Number(value) / (1024 * 1024)).toFixed(1)} MiB` : `${Number(value).toLocaleString('ko-KR')} B`
const groupKey = (item) => `${item.asset_id}:${item.scan_scope}`
function query(path, filters, offset = 0) {
  const values = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) if (value !== '' && value != null) values.set(key, value)
  values.set('limit', PAGE_SIZE); values.set('offset', offset)
  return `${path}?${values}`
}

// Each response belongs to its exact query. Polling starts after completion and
// never overlaps an earlier request; leaving a project aborts reads and timers.
function usePage(request, path, pollKind = '') {
  const [result, setResult] = useState(null)
  const [failure, setFailure] = useState(null)
  const [pending, setPending] = useState(false)
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    if (!path) return
    const controller = new AbortController(); let timer
    async function read() {
      setPending(true); setFailure(null)
      try {
        const data = await request(path, { signal: controller.signal })
        if (controller.signal.aborted) return
        setResult({ path, data })
        const active = (data.items || []).some((item) => activeStatuses.has(pollKind === 'projects' ? item.latest_job?.status : item.status))
        if (pollKind && active) timer = setTimeout(read, 3000)
      } catch (reason) { if (!controller.signal.aborted) setFailure({ path, message: reason.message }) }
      finally { if (!controller.signal.aborted) setPending(false) }
    }
    read()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [request, path, revision, pollKind])
  return { data: result?.path === path ? result.data : null, error: failure?.path === path ? failure.message : '', loading: pending || (!!path && result?.path !== path && failure?.path !== path), refresh: () => setRevision((value) => value + 1) }
}

function PageControls({ name, total, offset, busy, onPage }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const current = Math.floor(offset / PAGE_SIZE) + 1
  const [page, setPage] = useState(String(current))
  useEffect(() => setPage(String(current)), [current])
  return <div className="project-pagination" aria-label={`${name} 페이지`}>
    <span>총 {total}건 · {current} / {pages}쪽</span>
    <div className="action-row"><button className="secondary" disabled={busy || offset === 0} onClick={() => onPage(Math.max(0, offset - PAGE_SIZE))}>{name} 이전</button><button className="secondary" disabled={busy || offset + PAGE_SIZE >= total} onClick={() => onPage(offset + PAGE_SIZE)}>{name} 다음</button></div>
    {pages > 2 && <form onSubmit={(event) => { event.preventDefault(); const value = Number(page); if (Number.isInteger(value) && value >= 1 && value <= pages) onPage((value - 1) * PAGE_SIZE) }}><label>{name} 이동할 쪽<input type="number" min={1} max={pages} value={page} onChange={(event) => setPage(event.target.value)} disabled={busy} /></label><button className="table-button" disabled={busy}>{name} 이동</button></form>}
  </div>
}

function ReadState({ state, name }) {
  return <>{state.loading && !state.data && <p role="status">{name}을 불러오는 중…</p>}{state.error && <div className="project-error"><p className="form-error" role="alert">{name} 조회 실패: {state.error}</p><button className="secondary" onClick={state.refresh} disabled={state.loading}>다시 불러오기</button></div>}</>
}

function RunButtons({ run, onViewResult, onViewSbom, onDownload, busy }) {
  return <div className="action-row"><button className="table-button" onClick={() => onViewResult(run.sbom_id)}>CVE 결과</button><button className="table-button" onClick={() => onViewSbom(run.sbom_id)}>의존성 목록</button><button className="table-button" disabled={busy} onClick={() => onDownload(`/analyses/${run.id}/bundle`, `eolwatch-analysis-${run.id}.json`, `bundle-${run.id}`)}>원본 파일</button></div>
}

function ProjectDetail({ group: initialGroup, canEdit, request, download, onJobQueued, onChanged, onViewResult, onViewSbom, onCompare, onNewAnalysis, onViewWork }) {
  const metadata = usePage(request, query('/analyses/projects', { asset_id: initialGroup.asset_id, scan_scope: initialGroup.scan_scope }), 'projects')
  const group = metadata.data?.items.find((item) => groupKey(item) === groupKey(initialGroup)) || initialGroup
  const [tab, setTab] = useState('results')
  const [draft, setDraft] = useState({ q: '', date_from: '', date_to: '', status: 'ALL' })
  const [filters, setFilters] = useState(draft)
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [pending, setPending] = useState('')
  const [base, setBase] = useState(null)
  const [target, setTarget] = useState(null)
  const operation = useRef(null)
  const common = { asset_id: group.asset_id, scan_scope: group.scan_scope }
  const applied = { ...common, ...filters }
  if (tab !== 'jobs') delete applied.status
  const path = tab === 'results' ? query('/analyses/history', applied, offset) : tab === 'jobs' ? query('/analyses/job-history', applied, offset) : query('/analyses/uploads', common, offset)
  const page = usePage(request, path, tab === 'jobs' ? 'jobs' : '')
  const items = page.data?.items || []
  const chronological = base && target && (Date.parse(target.imported_at) > Date.parse(base.imported_at) || (Date.parse(target.imported_at) === Date.parse(base.imported_at) && target.id > base.id))
  const comparablePair = chronological && base.asset_id === target.asset_id && base.scan_scope === target.scan_scope
  useEffect(() => { operation.current?.abort(); operation.current = null; setPending(''); setMessage(''); return () => operation.current?.abort() }, [path])

  function switchTab(next) { operation.current?.abort(); operation.current = null; setPending(''); setError(''); setMessage(''); setTab(next); setOffset(0) }

  async function runOperation(key, action, complete) {
    if (operation.current) return
    const controller = new AbortController(); operation.current = controller; setPending(key); setError(''); setMessage('')
    try { const value = await action(controller.signal); if (!controller.signal.aborted) complete(value) }
    catch (reason) { if (!controller.signal.aborted) setError(reason.message || '요청을 처리하지 못했습니다.') }
    finally { if (operation.current === controller) operation.current = null; if (!controller.signal.aborted) setPending('') }
  }

  function downloadFile(path, filename, key) {
    runOperation(key, (signal) => download(path, filename, signal), () => setMessage(`${filename} 다운로드를 요청했습니다.`))
  }
  function reanalyse(upload) {
    if (!canEdit || upload.storage_status !== 'AVAILABLE') return
    runOperation(`upload-${upload.id}`, (signal) => request(`/analyses/uploads/${upload.id}/jobs`, { method: 'POST', signal }), (job) => { page.refresh(); metadata.refresh(); onJobQueued(job) })
  }
  function cancel(job) {
    if (!canEdit || !cancellableStatuses.has(job.status)) return
    runOperation(`cancel-${job.id}`, (signal) => request(`/analyses/jobs/${job.id}/cancel`, { method: 'POST', signal }), (updated) => { setMessage(`작업 #${updated.id}: ${jobLabels[updated.status] || updated.status}`); page.refresh(); metadata.refresh(); onChanged?.() })
  }
  function retry(job) {
    if (!canEdit || job.status !== 'FAILED') return
    runOperation(`retry-${job.id}`, (signal) => request(`/analyses/jobs/${job.id}/retry`, { method: 'POST', signal }), (queued) => { page.refresh(); metadata.refresh(); onJobQueued(queued) })
  }
  function startNew() {
    const separator = group.scan_scope.indexOf(':')
    onNewAnalysis({ assetId: group.asset_id, scanScope: group.scan_scope, projectName: group.project_name || (group.scan_scope.startsWith('source-') ? group.scan_scope.slice(separator + 1) : ''), targetPath: group.scan_scope.startsWith('ssh-') && separator >= 0 ? group.scan_scope.slice(separator + 1) : '', gitUrl: group.latest_job?.git_url || '', gitRef: group.latest_job?.git_ref || '' })
  }

  return <section className="panel project-detail" aria-label="선택한 프로젝트">
    <div className="project-heading"><div><span className="eyebrow">PROJECT HISTORY</span><h2>{group.asset_tag} · {scopeLabel(group.scan_scope)}</h2><p>{group.asset_name} · 같은 대상과 검사 범위의 모든 이력입니다.</p></div><div className="action-row">{onViewWork && <button className="secondary" onClick={() => onViewWork(group.asset_id)}>이 대상의 조치 목록</button>}{canEdit && isExecutableScope(group.scan_scope) && <button className="primary" onClick={startNew}>이 프로젝트 다시 검사</button>}</div></div>
    <ReadState state={metadata} name="선택한 프로젝트 정보" />
    <div className="project-summary"><div><strong>마지막 성공 검사</strong><p>{group.latest_analysis ? `검사 #${group.latest_analysis.id} · CVE ${group.latest_analysis.cve_count}건` : '성공한 검사 없음'}</p><small>{dateTime(group.latest_analysis?.imported_at)}</small></div><div><strong>마지막 작업</strong><p>{group.latest_job ? `#${group.latest_job.id} · ${jobLabels[group.latest_job.status] || group.latest_job.status}` : '작업 없음'}</p><small>{dateTime(group.latest_job?.requested_at)}</small>{group.latest_job?.error_message && <small>{group.latest_job.error_message}</small>}</div><div><strong>정기 검사</strong><p>{group.schedule ? group.schedule.enabled ? `${group.schedule.interval_minutes}분마다 실행` : '일시 중지' : '예약 없음'}</p><small>{group.schedule?.enabled ? `다음 실행 ${dateTime(group.schedule.next_run_at)}` : '인프라 검사에서 등록합니다.'}</small></div></div>
    <p className="project-help">CVE 수는 각 검사 당시 보고서 기준입니다. 이후 작업이 실패하거나 취소되어도 마지막 결과는 그대로입니다.</p>
    <div className="project-tabs" role="tablist" aria-label="이력 종류">{[['results', '검사 결과'], ['jobs', '작업 이력'], ['uploads', '저장된 ZIP']].map(([value, label]) => <button className="secondary" key={value} role="tab" aria-selected={tab === value} onClick={() => switchTab(value)}>{label}</button>)}</div>
    {tab !== 'uploads' && <form className="project-filters" onSubmit={(event) => { event.preventDefault(); if (draft.date_from && draft.date_to && draft.date_from > draft.date_to) { setError('조회 시작일은 종료일보다 늦을 수 없습니다.'); return } setError(''); setFilters({ ...draft }); setOffset(0) }}>
      <label>이력 검색<input value={draft.q} onChange={(event) => setDraft({ ...draft, q: event.target.value })} placeholder="대상 이름, 검사 범위" /></label><label>조회 시작일<input type="date" value={draft.date_from} onChange={(event) => setDraft({ ...draft, date_from: event.target.value })} /></label><label>조회 종료일<input type="date" value={draft.date_to} onChange={(event) => setDraft({ ...draft, date_to: event.target.value })} /></label>{tab === 'jobs' && <label>작업 상태<select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}><option value="ALL">전체 상태</option>{Object.entries(jobLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>}<button className="primary">조회</button>
    </form>}
    {error && <p className="form-error" role="alert">{error}</p>}{message && <p role="status" className="project-help">{message}</p>}
    <ReadState state={page} name={tab === 'results' ? '검사 결과' : tab === 'jobs' ? '작업 이력' : '저장된 ZIP'} />
    {tab === 'results' && <>
      <div className="project-comparison" aria-label="검사 전후 선택"><div>이전: {base ? `검사 #${base.id}` : '선택 안 함'} · 이후: {target ? `검사 #${target.id}` : '선택 안 함'}<small>다른 페이지의 검사도 고를 수 있습니다. 이후 검사는 이전 검사보다 나중 것이어야 합니다.</small></div><button className="primary" disabled={!comparablePair || !!pending} onClick={() => runOperation('compare', (signal) => onCompare(base.id, target.id, signal), () => {})}>{pending === 'compare' ? '비교 준비 중…' : '선택한 두 검사 비교'}</button>{(base || target) && <button className="secondary" onClick={() => { setBase(null); setTarget(null) }}>선택 해제</button>}{base && target && !comparablePair && <p className="form-error">같은 대상·범위에서 시간 순서에 맞는 두 검사를 고르세요.</p>}</div>
      <div className="table-wrap"><table aria-label="프로젝트 검사 결과"><thead><tr><th>검사 · 시각</th><th>도구 · 구성요소</th><th>CVE</th><th>결과 · 원본</th><th>전후 비교</th></tr></thead><tbody>{items.map((run) => <tr key={run.id}><td><strong>검사 #{run.id}</strong><small>{dateTime(run.imported_at)}</small><small>SBOM #{run.sbom_id}</small></td><td>{run.scanner} {run.scanner_version}<small>구성요소 {run.component_count}개</small></td><td>{run.cve_count}건</td><td><RunButtons run={run} onViewResult={onViewResult} onViewSbom={onViewSbom} onDownload={downloadFile} busy={!!pending} /></td><td><div className="action-row"><button className="table-button" aria-pressed={base?.id === run.id} onClick={() => setBase(run)}>이전으로</button><button className="table-button" aria-pressed={target?.id === run.id} onClick={() => setTarget(run)}>이후로</button></div></td></tr>)}</tbody></table></div>
    </>}
    {tab === 'jobs' && <div className="table-wrap"><table aria-label="검사 작업 이력"><thead><tr><th>작업 · 입력</th><th>상태</th><th>요청 · 종료</th><th>결과 · 관리</th></tr></thead><tbody>{items.map((job) => <tr key={job.id}><td><strong>작업 #{job.id}</strong><small>{job.upload_filename || job.target_path || (job.git_url ? `${job.git_url}${job.git_ref ? ` @ ${job.git_ref}` : ''}` : scopeLabel(job.scan_scope))}</small>{job.git_commit && <small>커밋 {job.git_commit.slice(0, 12)}</small>}{job.retry_of_id && <small>작업 #{job.retry_of_id} 재시도</small>}</td><td>{jobLabels[job.status] || job.status}{job.error_message && <small>{job.error_code}: {job.error_message}</small>}</td><td>{dateTime(job.requested_at)}<small>종료: {dateTime(job.finished_at)}</small></td><td><div className="action-row">{job.status === 'SUCCESS' && job.sbom_id && <><button className="table-button" onClick={() => onViewResult(job.sbom_id)}>CVE 결과</button><button className="table-button" onClick={() => onViewSbom(job.sbom_id)}>의존성 목록</button></>}{canEdit && job.status === 'FAILED' && <button className="table-button" disabled={!!pending} onClick={() => retry(job)}>{pending === `retry-${job.id}` ? '요청 중…' : '다시 검사'}</button>}{canEdit && (cancellableStatuses.has(job.status) || job.status === 'CANCEL_REQUESTED') && <button className="table-button" disabled={!!pending || job.status === 'CANCEL_REQUESTED'} onClick={() => cancel(job)}>{pending === `cancel-${job.id}` ? '취소 요청 중…' : job.status === 'CANCEL_REQUESTED' ? '취소 처리 중' : '검사 취소'}</button>}{job.status === 'IMPORTING' && <small>저장이 먼저 끝나면 취소되지 않을 수 있습니다.</small>}</div></td></tr>)}</tbody></table></div>}
    {tab === 'uploads' && <><p className="project-help">보관된 ZIP은 그대로 다시 검사할 수 있습니다. 다운로드와 재검사 때 SHA-256을 확인합니다.</p><div className="table-wrap"><table aria-label="저장된 ZIP 목록"><thead><tr><th>파일 · 등록 시각</th><th>원본 식별정보</th><th>검사 이력</th><th>관리</th></tr></thead><tbody>{items.map((upload) => <tr key={upload.id}><td><strong>{upload.filename}</strong><small>{dateTime(upload.created_at)}</small><small>{bytes(upload.size_bytes)} · {storageLabels[upload.storage_status] || upload.storage_status}</small></td><td><code>{upload.sha256}</code><small>업로드 #{upload.id}</small></td><td>{upload.job_count}회 요청<small>{upload.latest_job ? `최근 #${upload.latest_job.id} · ${jobLabels[upload.latest_job.status] || upload.latest_job.status}` : '요청 없음'}</small>{upload.latest_job?.sbom_id && <button className="table-button" onClick={() => onViewResult(upload.latest_job.sbom_id)}>최근 결과</button>}</td><td><div className="action-row"><button className="table-button" disabled={!!pending || upload.storage_status !== 'AVAILABLE'} onClick={() => downloadFile(`/analyses/uploads/${upload.id}/raw`, upload.filename, `raw-${upload.id}`)}>ZIP 다운로드</button>{canEdit ? <button className="table-button" disabled={!!pending || upload.storage_status !== 'AVAILABLE'} onClick={() => reanalyse(upload)}>{pending === `upload-${upload.id}` ? '재검사 요청 중…' : '이 ZIP 다시 검사'}</button> : <small>재검사는 관리자만</small>}</div></td></tr>)}</tbody></table></div></>}
    {!page.loading && !page.error && !items.length && <p className="project-empty">{tab === 'uploads' ? '저장된 ZIP이 없습니다.' : '조건에 맞는 이력이 없습니다.'}</p>}
    {page.data && <PageControls name={tab === 'results' ? '분석' : tab === 'jobs' ? '작업' : 'ZIP'} total={page.data.total} offset={offset} busy={page.loading} onPage={setOffset} />}
    <button className="secondary" disabled={page.loading} onClick={page.refresh}>새로고침</button>
  </section>
}

export default function ProjectHub({ assets, canEdit, request, download, onChanged, onJobQueued, onViewResult, onViewSbom, onCompare, onNewAnalysis, initialAssetId, initialScope, onSelectionChange, onViewWork }) {
  const [draft, setDraft] = useState({ asset_id: initialAssetId == null ? '' : String(initialAssetId), q: '' })
  const [filters, setFilters] = useState(draft)
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState(null)
  const [storageOpen, setStorageOpen] = useState(false)
  const groups = usePage(request, query('/analyses/projects', filters, offset), 'projects')
  const storage = usePage(request, canEdit && storageOpen ? '/analyses/storage' : null)
  useEffect(() => {
    if (initialAssetId == null || (selected?.asset_id === Number(initialAssetId) && (!initialScope || selected.scan_scope === initialScope))) return
    const value = { asset_id: String(initialAssetId), q: '' }; setDraft(value); setFilters(value); setOffset(0)
    const asset = assets.find((item) => String(item.id) === String(initialAssetId))
    setSelected(initialScope ? { asset_id: Number(initialAssetId), scan_scope: initialScope, asset_tag: asset?.asset_tag || `대상 #${initialAssetId}`, asset_name: asset?.name || '' } : null)
  }, [initialAssetId, initialScope])
  const items = groups.data?.items || []
  const group = selected ? items.find((item) => groupKey(item) === groupKey(selected)) || selected : null
  return <div className="project-hub">
    <section className="panel"><div className="project-heading"><div><span className="eyebrow">PROJECTS & HISTORY</span><h2>프로젝트별 검사 이력</h2><p>대상과 검사 범위별로 마지막 결과, 전체 이력, 저장된 입력 파일을 봅니다.</p></div>{canEdit && <button className="primary" onClick={() => onNewAnalysis({ assetId: filters.asset_id ? Number(filters.asset_id) : undefined })}>새 검사</button>}</div>
      <form className="project-filters" onSubmit={(event) => { event.preventDefault(); setFilters({ ...draft }); setOffset(0); setSelected(null) }}><label>대상<select value={draft.asset_id} onChange={(event) => setDraft({ ...draft, asset_id: event.target.value })}><option value="">모든 대상</option>{assets.map((asset) => <option value={asset.id} key={asset.id}>{asset.asset_tag} · {asset.name}</option>)}</select></label><label>프로젝트 검색<input value={draft.q} onChange={(event) => setDraft({ ...draft, q: event.target.value })} placeholder="대상, 프로젝트 이름, 검사 범위" /></label><button className="primary">프로젝트 조회</button><button type="button" className="secondary" disabled={groups.loading} onClick={groups.refresh}>프로젝트 새로고침</button></form>
      <ReadState state={groups} name="프로젝트 목록" />
      <div className="table-wrap"><table aria-label="프로젝트 목록"><thead><tr><th>대상 · 검사 범위</th><th>마지막 결과</th><th>마지막 작업</th><th>이력 · 정기 검사</th><th>보기</th></tr></thead><tbody>{items.map((item) => <tr key={groupKey(item)} className={group && groupKey(group) === groupKey(item) ? 'project-selected' : ''}><td><strong>{item.asset_tag} · {item.asset_name}</strong><small>{scopeLabel(item.scan_scope)}</small></td><td>{item.latest_analysis ? <>CVE {item.latest_analysis.cve_count}건<small>검사 #{item.latest_analysis.id} · {dateTime(item.latest_analysis.imported_at)}</small></> : '성공한 검사 없음'}</td><td>{item.latest_job ? <>{jobLabels[item.latest_job.status] || item.latest_job.status}<small>작업 #{item.latest_job.id} · {dateTime(item.latest_job.requested_at)}</small></> : '작업 없음'}</td><td>분석 {item.analysis_count} · 작업 {item.job_count} · ZIP {item.upload_count}<small>{item.schedule ? item.schedule.enabled ? `예약 ${item.schedule.interval_minutes}분` : '예약 일시 중지' : '예약 없음'}</small></td><td><button className="table-button" aria-label={`${item.asset_tag} ${scopeLabel(item.scan_scope)} 이력 보기`} onClick={() => { setSelected(item); onSelectionChange?.({ assetId: item.asset_id, scanScope: item.scan_scope }) }}>이력 보기</button></td></tr>)}</tbody></table></div>
      {!groups.loading && !groups.error && !items.length && <p className="project-empty">조건에 맞는 프로젝트가 없습니다.{canEdit ? ' 새 검사에서 ZIP을 올리거나 서버 경로를 등록하세요.' : '관리자가 검사를 실행하면 여기서 결과를 볼 수 있습니다.'}</p>}
      {groups.data && <PageControls name="프로젝트" total={groups.data.total} offset={offset} busy={groups.loading} onPage={setOffset} />}
    </section>
    {group ? <ProjectDetail key={groupKey(group)} group={group} canEdit={canEdit} request={request} download={download} onChanged={() => { groups.refresh(); onChanged?.() }} onJobQueued={(job) => { groups.refresh(); onJobQueued(job) }} onViewResult={onViewResult} onViewSbom={onViewSbom} onCompare={onCompare} onNewAnalysis={onNewAnalysis} onViewWork={onViewWork} /> : <p className="project-empty">프로젝트의 ‘이력 보기’를 누르면 결과·작업·저장된 ZIP이 나옵니다.</p>}
    {canEdit && <section className="panel project-storage"><div className="project-heading"><h3>검사 파일 보관 현황</h3><button className="secondary" onClick={() => { if (storageOpen) storage.refresh(); else setStorageOpen(true) }} disabled={storage.loading}>보관 현황 {storageOpen ? '새로고침' : '조회'}</button></div>{storageOpen && <><ReadState state={storage} name="보관 현황" />{storage.data && <><dl>{[['보관 파일', 'files'], ['연결된 파일', 'referenced_files'], ['미연결 파일', 'unreferenced_files'], ['누락 파일', 'missing_files'], ['크기 불일치', 'size_mismatch_files'], ['접근 불가', 'unsafe_files'], ['임시 파일', 'temp_files']].map(([label, key]) => <div key={key}><dt>{label}</dt><dd>{storage.data[key] ?? '미확인'}</dd></div>)}<div><dt>보관 용량</dt><dd>{bytes(storage.data.bytes)}</dd></div><div><dt>디스크 여유</dt><dd>{bytes(storage.data.free_disk_bytes)}</dd></div></dl><p className="project-help">확인 시각 {dateTime(storage.data.checked_at)} · 보관 상태와 크기 기준이며 전체 파일 내용 검증은 수행하지 않았습니다.</p></>}</>}</section>}
  </div>
}
