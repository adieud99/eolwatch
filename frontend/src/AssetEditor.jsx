import { useEffect, useRef, useState } from 'react'
import './AssetEditor.css'

const types = { server: '서버', storage: '스토리지', network: '네트워크', security: '보안', vm: '가상머신', cloud: '클라우드', other: '기타' }
const textFields = [['ip_address', '서버 주소 (IP 또는 도메인)'], ['ssh_username', 'SSH 사용자명']]
const editable = ['asset_tag', 'name', 'asset_type', ...textFields.map(([key]) => key), 'ssh_port', 'monitored']
const draftOf = (asset) => Object.fromEntries(editable.map((key) => [key, key === 'monitored' ? Boolean(asset[key]) : asset[key] ?? (key === 'ssh_port' ? 22 : '')]))
const normalize = (key, value) => key === 'monitored' ? value : key === 'ssh_port' ? (value === '' ? null : Number(value)) : typeof value === 'string' ? value.trim() || null : value

export default function AssetEditor({ asset, canEdit, request, onSaved, onClose, onViewCve, onViewSbom }) {
  const [current, setCurrent] = useState(asset)
  const [draft, setDraft] = useState(() => draftOf(asset))
  const [ready, setReady] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const [retry, setRetry] = useState(0)
  const [timeline, setTimeline] = useState([])
  const [sboms, setSboms] = useState([])
  const [detailTab, setDetailTab] = useState('overview')
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [purge, setPurge] = useState(false)
  const busy = useRef(false)
  const mutation = useRef(null)
  const panel = useRef(null)
  useEffect(() => { panel.current?.scrollIntoView?.({ block: 'start', behavior: 'smooth' }) }, [asset.id])

  useEffect(() => {
    const controller = new AbortController()
    setReady(false); setLoading(true); setPending(false); setError(''); setDeleteOpen(false); setConfirmation(''); setPurge(false)
    request(`/assets/${asset.id}`, { signal: controller.signal }).then((fresh) => {
      if (!controller.signal.aborted) { setCurrent(fresh); setDraft(draftOf(fresh)); setReady(true) }
    }).catch((err) => { if (!controller.signal.aborted) setError(`서버 정보를 불러오지 못했습니다. ${err.message}`) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    request(`/assets/${asset.id}/timeline`, { signal: controller.signal }).then((events) => {
      if (!controller.signal.aborted && Array.isArray(events)) setTimeline(events)
    }).catch(() => {})
    request('/sboms', { signal: controller.signal }).then((items) => {
      if (!controller.signal.aborted && Array.isArray(items)) setSboms(items.filter((item) => item.asset_id === asset.id))
    }).catch(() => {})
    setDetailTab('overview')
    return () => { controller.abort(); mutation.current?.abort(); busy.current = false }
  }, [asset.id, request, retry])

  function change(key, value) { setDraft((previous) => ({ ...previous, [key]: value })); setError('') }

  async function save(event) {
    event.preventDefault()
    if (!canEdit || !ready || busy.current) return
    if (!draft.asset_tag.trim() || !draft.name.trim()) { setError('서버 번호와 서버 이름을 입력하세요.'); return }
    if (!Number.isInteger(Number(draft.ssh_port)) || Number(draft.ssh_port) < 1 || Number(draft.ssh_port) > 65535) { setError('SSH 포트는 1~65535 사이 정수여야 합니다.'); return }
    const values = Object.fromEntries(editable.map((key) => [key, normalize(key, draft[key])]).filter(([key, value]) => value !== normalize(key, current[key] ?? (key === 'monitored' ? false : ''))))
    busy.current = true; setPending(true); setError('')
    const controller = new AbortController(); mutation.current = controller
    try {
      const updated = await request(`/assets/${asset.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values), signal: controller.signal })
      if (!controller.signal.aborted) onSaved(updated)
    } catch (err) { if (!controller.signal.aborted) setError(`서버 정보를 저장하지 못했습니다. ${err.message}`) }
    finally { if (!controller.signal.aborted) { busy.current = false; setPending(false) } }
  }

  async function remove(event) {
    event.preventDefault()
    if (!canEdit || !ready || busy.current || confirmation !== current.asset_tag) return
    busy.current = true; setPending(true); setError('')
    const controller = new AbortController(); mutation.current = controller
    try {
      await request(`/assets/${asset.id}${purge ? '?purge=true' : ''}`, { method: 'DELETE', signal: controller.signal })
      if (!controller.signal.aborted) onSaved(null)
    } catch (err) { if (!controller.signal.aborted) setError(`서버를 삭제하지 못했습니다. ${err.message}`) }
    finally { if (!controller.signal.aborted) { busy.current = false; setPending(false) } }
  }

  return <section ref={panel} className="asset-editor panel" aria-label="서버 정보 관리">
    <div className="asset-editor-heading"><h3>{current.asset_tag} · 서버 정보</h3><button type="button" className="secondary" disabled={pending} onClick={onClose}>닫기</button></div>
    {loading && <p role="status">최신 서버 정보를 불러오는 중입니다.</p>}
    {error && <p role="alert" className="form-error">{error}</p>}
    {!ready && !loading && <button type="button" className="secondary" onClick={() => setRetry((value) => value + 1)}>서버 정보 다시 불러오기</button>}
    <nav className="asset-detail-tabs" aria-label="서버 상세 탭"><button type="button" className={detailTab === 'overview' ? 'active' : ''} onClick={() => setDetailTab('overview')}>기본 정보</button><button type="button" className={detailTab === 'sbom' ? 'active' : ''} onClick={() => setDetailTab('sbom')}>의존성 목록 ({sboms.length})</button><button type="button" className={detailTab === 'timeline' ? 'active' : ''} onClick={() => setDetailTab('timeline')}>타임라인 ({timeline.length})</button></nav>
    {detailTab === 'overview' && !canEdit && <dl className="asset-editor-read"><dt>서버 이름</dt><dd>{current.name}</dd><dt>유형</dt><dd>{types[current.asset_type] || current.asset_type}</dd>{textFields.map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{current[key] || '미입력'}</dd></div>)}<dt>SSH 포트</dt><dd>{current.ssh_port}</dd><dt>검사 대상</dt><dd>{current.monitored ? '사용' : '해제'}</dd></dl>}
    {detailTab === 'overview' && <div className="asset-summary"><strong>{current.name}</strong><span>{types[current.asset_type] || current.asset_type} · {current.ip_address ? `${current.ip_address}:${current.ssh_port}` : 'IP 미입력'}</span><span>SBOM {current.sbom_count ?? sboms.length}건 · CVE {current.vulnerability_count ?? 0}건</span><div className="action-row"><button type="button" className="table-button" onClick={() => onViewCve?.(asset.id)}>CVE 조치 보기</button><button type="button" className="table-button" disabled={!sboms.length} onClick={() => onViewSbom?.(sboms[0]?.id)}>의존성 목록 보기</button></div></div>}
    {detailTab === 'sbom' && <section className="asset-related"><h4>의존성 목록 (SBOM)</h4>{sboms.length ? <ul>{sboms.map((item) => <li key={item.id}><strong>SBOM #{item.id}</strong><span>{item.bom_format} {item.spec_version} · 구성요소 {item.component_count}개 · 의존관계 {item.dependency_count}개</span><small>{item.imported_at ? new Date(item.imported_at).toLocaleString('ko-KR') : '저장 시각 미기록'}</small><button type="button" className="table-button" onClick={() => onViewSbom?.(item.id)}>목록 보기</button></li>)}</ul> : <p>연결된 의존성 목록이 없습니다.</p>}</section>}
    {canEdit && !deleteOpen && <form onSubmit={save}>
      <fieldset disabled={!ready || pending} className="asset-editor-grid">
        <label>서버 번호<input value={draft.asset_tag} maxLength={80} required onChange={(e) => change('asset_tag', e.target.value)} /></label>
        <label>서버 이름<input value={draft.name} maxLength={160} required onChange={(e) => change('name', e.target.value)} /></label>
        <label>유형<select value={draft.asset_type} onChange={(e) => change('asset_type', e.target.value)}>{Object.entries(types).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        {textFields.map(([key, label]) => <label key={key}>{label}<input value={draft[key]} maxLength={key === 'ssh_username' ? 80 : 64} onChange={(e) => change(key, e.target.value)} /></label>)}
        <label>SSH 포트<input type="number" min="1" max="65535" step="1" required value={draft.ssh_port} onChange={(e) => change('ssh_port', e.target.value)} /></label>
        <label className="asset-editor-check"><input type="checkbox" checked={draft.monitored} onChange={(e) => change('monitored', e.target.checked)} />검사 대상으로 사용</label>
      </fieldset>
      <div className="asset-editor-heading"><button type="submit" className="primary" disabled={!ready || pending}>{pending ? '저장 중…' : '서버 변경 저장'}</button><button type="button" className="secondary" disabled={!ready || pending} onClick={() => { setDeleteOpen(true); setError('') }}>서버 삭제…</button></div>
    </form>}
    {canEdit && deleteOpen && <form onSubmit={remove} className="asset-editor-delete"><h4>서버 삭제 확인</h4><p>이력이 없는 서버만 바로 삭제됩니다. 검사·점검·결과 이력이 있으면 아래 '이력 포함 삭제'를 선택해야 하며, 그 경우 검사 결과·CVE 조치 기록·저장된 ZIP·AI 요약이 함께 지워집니다.</p><label className="asset-editor-check"><input type="checkbox" checked={purge} disabled={pending} onChange={(e) => setPurge(e.target.checked)} />이력 포함 삭제 (검사 결과와 조치 기록까지 모두 삭제)</label><p>삭제할 서버 번호 <strong>{current.asset_tag}</strong>를 입력하세요. 삭제 후 되돌릴 수 없습니다.</p><label>삭제 확인 서버 번호<input autoComplete="off" value={confirmation} disabled={pending} onChange={(e) => setConfirmation(e.target.value)} /></label><div className="asset-editor-heading"><button type="submit" disabled={pending || confirmation !== current.asset_tag}>서버 영구 삭제</button><button type="button" className="secondary" disabled={pending} onClick={() => { setDeleteOpen(false); setConfirmation(''); setError('') }}>삭제 취소</button></div></form>}
    {detailTab === 'timeline' && <section className="asset-timeline" aria-label="서버 타임라인"><h4>서버 타임라인</h4>{timeline.length ? <ol>{timeline.slice(0, 20).map((event, index) => <li key={`${event.type}-${event.at}-${index}`}><strong>{event.title}</strong><small>{event.at ? new Date(event.at).toLocaleString('ko-KR') : '시각 미기록'}</small><span>{event.detail}</span></li>)}</ol> : <p>검사·점검·SBOM·조치 이력이 없습니다.</p>}</section>}
  </section>
}
