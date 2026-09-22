import { useEffect, useRef, useState } from 'react'
import './Workspace.css'

const qualityNames = { serial_number: '문서 식별자', timestamp: '생성 시각', authors: '작성자', tools: '생성 도구', component_names: '구성요소 이름', component_versions: '버전', component_suppliers: '공급자', component_unique_ids: '구성요소 식별자', dependency_relationships: '의존관계', license_information: '라이선스', document_namespace: '문서 네임스페이스', creation_info: '생성 정보', package_names: '패키지 이름', package_versions: '패키지 버전' }
const display = (value) => typeof value === 'string' ? value : JSON.stringify(value)
const when = (value) => value ? new Date(value).toLocaleString('ko-KR') : '미기록'

function Pager({ total, offset, size, busy, onChange, label }) {
  return <div className="workspace-pagination"><span>{total}건 · {total ? offset + 1 : 0}–{Math.min(offset + size, total)}건 표시</span><div className="action-row"><button className="table-button" aria-label={`${label} 이전 페이지`} disabled={busy || !offset} onClick={() => onChange(Math.max(0, offset - size))}>이전</button><button className="table-button" aria-label={`${label} 다음 페이지`} disabled={busy || offset + size >= total} onClick={() => onChange(offset + size)}>다음</button></div></div>
}

function ComponentDetail({ component, onClose }) {
  const panel = useRef(null)
  useEffect(() => { panel.current?.scrollIntoView?.({ block: 'start', behavior: 'smooth' }) }, [component.id])
  return <section className="workspace-detail" aria-label="구성요소 상세" ref={panel}>
    <div className="workspace-title"><div><h3>{component.name} {component.version}</h3><p>검사 당시 구성요소 · {component.supplier || '공급자 미기록'}</p></div><button className="secondary" onClick={onClose}>상세 닫기</button></div>
    <dl className="workspace-metadata"><dt>PURL</dt><dd><code>{component.purl || '미기록'}</code></dd><dt>CPE</dt><dd><code>{component.cpe || '미기록'}</code></dd><dt>문서 내 식별자</dt><dd><code>{component.bom_ref}</code></dd><dt>라이선스</dt><dd>{component.licenses?.map(display).join(', ') || '미기록'}</dd><dt>해시</dt><dd>{component.hashes?.length ? component.hashes.map((hash, index) => <code key={index} className="workspace-line">{display(hash)}</code>) : '미기록'}</dd></dl>
  </section>
}

export default function SbomExplorer({ sbomId, request, download, onClose, onViewCve }) {
  const [metadata, setMetadata] = useState(null)
  const [page, setPage] = useState({ items: [], total: 0 })
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [metadataError, setMetadataError] = useState('')
  const [detailError, setDetailError] = useState('')
  const [reload, setReload] = useState(0)
  const [downloading, setDownloading] = useState(false)
  const detailRequest = useRef(null)
  const downloadRequest = useRef(null)
  useEffect(() => () => { detailRequest.current?.abort(); downloadRequest.current?.abort() }, [])
  useEffect(() => {
    const controller = new AbortController(); setMetadataError('')
    request(`/sboms/${sbomId}/detail`, { signal: controller.signal }).then((result) => { if (!controller.signal.aborted) setMetadata(result) }).catch((reason) => { if (!controller.signal.aborted) setMetadataError(reason.message) })
    return () => controller.abort()
  }, [sbomId, request, reload])
  useEffect(() => {
    const controller = new AbortController(); setBusy(true); setError(''); setPage({ items: [], total: 0 })
    request(`/sboms/${sbomId}/component-page?q=${encodeURIComponent(query)}&limit=50&offset=${offset}`, { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setPage(result) })
      .catch((reason) => { if (!controller.signal.aborted) setError(reason.message) })
      .finally(() => { if (!controller.signal.aborted) setBusy(false) })
    return () => controller.abort()
  }, [sbomId, query, offset, request, reload])

  async function choose(id) {
    const controller = new AbortController(); detailRequest.current?.abort(); detailRequest.current = controller; setDetailError('')
    try { const item = await request(`/sboms/${sbomId}/components/${id}`, { signal: controller.signal }); if (!controller.signal.aborted) setSelected(item) }
    catch (reason) { if (!controller.signal.aborted) setDetailError(reason.message) }
  }
  async function raw() {
    if (downloadRequest.current) return
    const controller = new AbortController(); downloadRequest.current = controller; setDownloading(true); setDetailError('')
    try { await download(`/sboms/${sbomId}/raw`, `eolwatch-sbom-${sbomId}.json`, controller.signal) }
    catch (reason) { if (!controller.signal.aborted) setDetailError(reason.message) }
    finally { if (downloadRequest.current === controller) downloadRequest.current = null; if (!controller.signal.aborted) setDownloading(false) }
  }
  return <section className="panel workspace-panel" aria-label="SBOM 상세 탐색">
    <div className="workspace-title"><div><span className="eyebrow">SBOM EXPLORER</span><h2>SBOM #{sbomId} 의존성 목록</h2><p>{metadata?.asset ? `${metadata.asset.asset_tag} · ${metadata.asset.name}` : '대상 미연결'} · {metadata?.bom_format} {metadata?.spec_version}</p></div><div className="action-row"><button className="secondary" disabled={downloading} onClick={raw}>{downloading ? '다운로드 중…' : 'SBOM 원본 JSON'}</button><button className="secondary" onClick={() => onViewCve(sbomId)}>이 SBOM의 CVE 보기</button><button className="table-button" onClick={onClose}>상세 탐색 닫기</button></div></div>
    {metadataError && <p className="form-error" role="alert">{metadataError}</p>}
    {metadata && <><dl className="workspace-metadata"><dt>문서 식별자</dt><dd><code>{metadata.serial_number}</code></dd><dt>생성 / 등록</dt><dd>{when(metadata.generated_at)} / {when(metadata.imported_at)}</dd><dt>구성요소 / 관계</dt><dd>{metadata.component_count}개 / {metadata.dependency_count}개</dd><dt>SBOM 품질</dt><dd>{metadata.quality_score}점 · {metadata.quality_details?.profile || '내부 품질 프로파일'}</dd></dl><details className="workspace-quality"><summary>품질 검사 항목과 누락 정보</summary><ul>{Object.entries(metadata.quality_details?.checks || {}).map(([name, passed]) => <li key={name}><strong>{passed ? '충족' : '누락'}</strong> · {qualityNames[name] || name}</li>)}</ul><p className="workspace-help">품질 점수는 기록의 완전성을 점검하며 취약점이 없음을 뜻하지 않습니다.</p></details></>}
    <form className="workspace-search" onSubmit={(event) => { event.preventDefault(); setQuery(search.trim()); setOffset(0); setSelected(null) }}><label>구성요소 검색<input value={search} maxLength={200} onChange={(event) => setSearch(event.target.value)} placeholder="패키지 이름, 버전, PURL, CPE, 공급자" /></label><button className="primary">검색</button></form>
    {error && <p className="form-error" role="alert">{error} <button className="table-button" onClick={() => setReload((value) => value + 1)}>다시 조회</button></p>}
    {detailError && <p className="form-error" role="alert">{detailError}</p>}
    {selected && <ComponentDetail key={selected.id} component={selected} onClose={() => { detailRequest.current?.abort(); setSelected(null) }} />}
    {busy ? <p role="status">구성요소를 불러오는 중…</p> : <div className="table-wrap"><table aria-label="의존성 목록"><thead><tr><th>패키지</th><th>검사 당시 버전</th><th>공급자</th><th>라이선스</th><th>상세</th></tr></thead><tbody>{page.items.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.purl || item.bom_ref}</small></td><td>{item.version || '미기록'}</td><td>{item.supplier || '미기록'}</td><td>{item.licenses?.map(display).join(', ') || '미기록'}</td><td><button className="table-button" aria-label={`${item.name} ${item.version || ''} 상세 보기`} onClick={() => choose(item.id)}>상세·관계</button></td></tr>)}{!page.items.length && !error && <tr><td colSpan={5} className="empty">검색 조건에 맞는 구성요소가 없습니다.</td></tr>}</tbody></table></div>}
    <Pager total={page.total} offset={offset} size={50} busy={busy} onChange={setOffset} label="구성요소" />
  </section>
}
