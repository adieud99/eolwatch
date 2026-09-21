import { useEffect, useRef, useState } from 'react'
import './LifecycleCatalog.css'

const time = (value) => value ? new Date(value).toLocaleString('ko-KR') : '미기록'
const safeLink = (value) => /^https?:\/\//i.test(value || '') ? <a href={value} target="_blank" rel="noreferrer">{value}</a> : '미기록'
const emptyPage = { items: [], total: 0 }

function useRead(path, api, epoch) {
  const [result, setResult] = useState({ path: null, epoch: null, data: null, loading: false, error: '' })
  useEffect(() => {
    if (!path) { setResult({ path, epoch, data: null, loading: false, error: '' }); return }
    const controller = new AbortController()
    setResult({ path, epoch, data: null, loading: true, error: '' })
    api(path, { signal: controller.signal }).then((data) => {
      if (!controller.signal.aborted) setResult({ path, epoch, data, loading: false, error: '' })
    }).catch((error) => { if (!controller.signal.aborted) setResult({ path, epoch, data: null, loading: false, error: error.message }) })
    return () => controller.abort()
  }, [path, api, epoch])
  return result.path === path && result.epoch === epoch ? result : { data: null, loading: Boolean(path), error: '' }
}

function ReadState({ value }) {
  return <>{value.loading && <p role="status">자료를 불러오는 중…</p>}{value.error && <p role="alert" className="form-error">{value.error}</p>}</>
}

function Pages({ total, offset, limit, loading, onChange, name }) {
  return <div className="lifecycle-pages"><span>{total}건 · {total ? offset + 1 : 0}–{Math.min(offset + limit, total)}건</span><div><button className="table-button" disabled={loading || !offset} aria-label={`${name} 이전 페이지`} onClick={() => onChange(Math.max(0, offset - limit))}>이전</button><button className="table-button" disabled={loading || offset + limit >= total} aria-label={`${name} 다음 페이지`} onClick={() => onChange(offset + limit)}>다음</button></div></div>
}

function Provenance({ cache }) {
  if (!cache) return null
  return <div className="lifecycle-provenance">
    <p><strong>{!cache.available ? '공개 자료 미수집' : cache.stale ? '오래된 공개 자료 · 다시 조회 필요' : '저장된 공개 자료'}</strong></p>
    {cache.last_error && <p role="alert" className="form-error">{cache.last_error} · 실패 시각 {time(cache.last_error_at)}</p>}
    <dl><dt>본문 수집 시각</dt><dd>{time(cache.fetched_at)}</dd><dt>최근 조회 시각</dt><dd>{time(cache.last_checked_at)}</dd><dt>제공처 응답 생성 시각</dt><dd>{time(cache.provider_generated_at)}</dd><dt>제공처 제품 변경 시각</dt><dd>{time(cache.provider_last_modified)}</dd><dt>공개 데이터 출처</dt><dd>{safeLink(cache.source_url)}</dd><dt>원본 SHA-256</dt><dd><code>{cache.content_sha256 || '미기록'}</code></dd></dl>
  </div>
}

export default function LifecycleCatalog({ api, onError, onRefresh, isAdmin }) {
  const [localDraft, setLocalDraft] = useState('')
  const [localQuery, setLocalQuery] = useState('')
  const [localOffset, setLocalOffset] = useState(0)
  const [selected, setSelected] = useState(null)
  const [publicDraft, setPublicDraft] = useState('')
  const [publicQuery, setPublicQuery] = useState('')
  const [publicOffset, setPublicOffset] = useState(0)
  const [slug, setSlug] = useState('')
  const [cycle, setCycle] = useState('')
  const [previewPath, setPreviewPath] = useState(null)
  const [historyOffset, setHistoryOffset] = useState(0)
  const [epoch, setEpoch] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const mutation = useRef(null)
  useEffect(() => () => mutation.current?.abort(), [])
  const local = useRead(`/lifecycle-catalog/local-products?q=${encodeURIComponent(localQuery)}&limit=20&offset=${localOffset}`, api, epoch)
  const catalog = useRead(`/lifecycle-catalog/products?q=${encodeURIComponent(publicQuery)}&limit=50&offset=${publicOffset}`, api, epoch)
  const detail = useRead(slug ? `/lifecycle-catalog/products/${encodeURIComponent(slug)}` : null, api, epoch)
  const preview = useRead(previewPath, api, epoch)
  const history = useRead(selected ? `/lifecycle-catalog/applications?product_id=${selected.id}&limit=10&offset=${historyOffset}` : null, api, epoch)
  const localPage = local.data || emptyPage
  const publicPage = catalog.data || emptyPage
  const historyPage = history.data || emptyPage
  const releases = detail.data?.releases || []
  const release = releases.find((item) => item.name === cycle)
  const current = preview.data

  function chooseLocal(item) { setSelected(item); setHistoryOffset(0); setPreviewPath(null); setNotice(''); setError('') }
  function choosePublic(value) { setSlug(value); setCycle(''); setPreviewPath(null); setNotice(''); setError('') }
  async function mutate(path, body, success) {
    if (!isAdmin || mutation.current) return
    const controller = new AbortController(); mutation.current = controller; setBusy(true); setError(''); setNotice('')
    try {
      await api(path, { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (!controller.signal.aborted) {
        setNotice(success)
        if (path.endsWith('/apply')) {
          setHistoryOffset(0)
          Promise.resolve(onRefresh?.()).catch((reason) => onError?.(reason.message))
        }
      }
    } catch (reason) {
      if (!controller.signal.aborted) { setError(reason.message); onError?.(reason.message) }
    } finally {
      if (mutation.current === controller) mutation.current = null
      if (!controller.signal.aborted) { setBusy(false); setPreviewPath(null); setEpoch((value) => value + 1) }
    }
  }
  function showPreview() {
    if (selected && slug && cycle) {
      setError(''); setNotice('')
      setPreviewPath(`/lifecycle-catalog/preview/${selected.id}?product_slug=${encodeURIComponent(slug)}&release_cycle=${encodeURIComponent(cycle)}`)
    }
  }
  function apply() {
    if (!current?.can_apply || current.product.id !== selected?.id || current.product_slug !== slug || current.release_cycle !== cycle) return
    mutate('/lifecycle-catalog/apply', { product_id: current.product.id, product_slug: current.product_slug, release_cycle: current.release_cycle,
      expected_product_revision: current.expected_product_revision, expected_catalog_sha256: current.expected_catalog_sha256 }, '선택한 공개 지원 종료일을 적용하고 원본 근거를 이력에 저장했습니다.')
  }

  return <section className="panel lifecycle-catalog" aria-label="공개 지원 일정 연결">
    <div className="lifecycle-heading"><div><span className="eyebrow">LIFECYCLE CATALOG</span><h2>공개 지원 일정 연결</h2></div><button className="secondary" disabled={busy} onClick={() => { setPreviewPath(null); setEpoch((value) => value + 1) }}>저장 자료 다시 보기</button></div>
    <p>등록 제품을 공개 제품의 지원 주기에 직접 연결하고, 기존 날짜와 비교한 뒤 적용합니다. 조회에는 공개 제품 식별자만 사용하며 설치 버전·SBOM을 전송하지 않습니다.</p>
    {!isAdmin && <p className="lifecycle-note">조회 계정은 저장 자료·비교·적용 이력을 볼 수 있습니다. 공개 자료 갱신과 날짜 적용은 관리자가 실행합니다.</p>}
    {notice && <p role="status" className="lifecycle-notice">{notice}</p>}{error && <p role="alert" className="form-error">{error}</p>}
    <fieldset disabled={busy} className="lifecycle-step"><legend>1. 등록 제품 선택</legend>
      <form className="lifecycle-search" onSubmit={(event) => { event.preventDefault(); setLocalQuery(localDraft.trim()); setLocalOffset(0); setSelected(null); setPreviewPath(null) }}><label>등록 제품 검색<input maxLength={200} value={localDraft} onChange={(event) => setLocalDraft(event.target.value)} placeholder="제품명, 제조사, 버전, PURL" /></label><button className="primary">등록 제품 검색</button></form>
      <ReadState value={local} />
      {!local.loading && !local.error && <div className="table-wrap"><table aria-label="지원 일정 연결 대상"><thead><tr><th>등록 제품</th><th>현재 보안지원 종료</th><th>공개 일정 적용 이력</th><th>선택</th></tr></thead><tbody>{localPage.items.map((item) => <tr key={item.id} aria-selected={selected?.id === item.id}><td><strong>{item.name}</strong><small>{item.version} · {item.vendor || '제조사 미기록'}</small></td><td>{item.security_end_date || '미확인'}</td><td>{item.latest_application ? `${item.latest_application.product_slug} / ${item.latest_application.release_cycle}` : '적용 이력 없음'}</td><td><button className="table-button" aria-label={`${item.name} ${item.version} 일정 연결`} onClick={() => chooseLocal(item)}>일정 연결</button></td></tr>)}{!localPage.items.length && <tr><td colSpan={4}>검색 결과가 없습니다.</td></tr>}</tbody></table></div>}
      <Pages total={localPage.total} offset={localOffset} limit={20} loading={local.loading} name="등록 제품" onChange={(value) => { setLocalOffset(value); setSelected(null); setPreviewPath(null) }} />
    </fieldset>
    {selected && <>
      <fieldset disabled={busy} className="lifecycle-step"><legend>2. 공개 제품과 지원 주기 선택</legend>
        <h3>{selected.name} {selected.version}</h3><p className="lifecycle-note">자동 이름 추정은 사용하지 않습니다. 제품·배포판·에디션과 지원 주기가 일치하는지 공식 정책에서 확인하세요.</p>
        <form className="lifecycle-search" onSubmit={(event) => { event.preventDefault(); setPublicQuery(publicDraft.trim()); setPublicOffset(0) }}><label>공개 제품 검색<input maxLength={100} value={publicDraft} onChange={(event) => setPublicDraft(event.target.value)} placeholder="PostgreSQL, Python, Ubuntu…" /></label><button className="secondary">공개 제품 검색</button>{isAdmin && <button className="secondary" type="button" onClick={() => mutate('/lifecycle-catalog/refresh', { product_slug: null }, '공개 제품 목록을 갱신했습니다.')}>공개 제품 목록 갱신</button>}</form>
        <ReadState value={catalog} /><Provenance cache={catalog.data?.cache} />
        <label className="lifecycle-selection">공개 제품<select value={slug} onChange={(event) => choosePublic(event.target.value)}><option value="">공개 제품을 선택하세요</option>{slug && !publicPage.items.some((item) => item.name === slug) && <option value={slug}>{slug} (선택 유지)</option>}{publicPage.items.map((item) => <option key={item.name} value={item.name}>{item.label} · {item.name}</option>)}</select></label>
        <Pages total={publicPage.total} offset={publicOffset} limit={50} loading={catalog.loading} name="공개 제품" onChange={setPublicOffset} />
        {slug && <><div className="lifecycle-heading"><h4>공개 일정 · {slug}</h4>{isAdmin && <button className="secondary" onClick={() => mutate('/lifecycle-catalog/refresh', { product_slug: slug }, '선택한 공개 제품의 지원 일정을 조회했습니다.')}>공개 일정 조회</button>}</div><ReadState value={detail} /><Provenance cache={detail.data?.cache} />
          <p>공식 지원 정책: {safeLink(detail.data?.product?.links?.releasePolicy)}</p>
          <label className="lifecycle-selection">지원 주기<select value={cycle} onChange={(event) => { setCycle(event.target.value); setPreviewPath(null) }}><option value="">지원 주기를 선택하세요</option>{releases.map((item) => <option key={item.name} value={item.name}>{item.label || item.name}</option>)}</select></label>
          {release && <dl className="lifecycle-phases"><dt>일반 기능 지원 종료</dt><dd>{release.eoasFrom || '날짜 미공개 / 단계 미제공'}</dd><dt>표준 지원 종료 · 보안 포함</dt><dd>{release.eolFrom || '날짜 미확정'} · {release.isEol ? '제공처에서 종료로 표시' : '제공처에서 미종료로 표시'}</dd><dt>연장 지원 종료</dt><dd>{release.eoesFrom || '날짜 미공개 / 대상 아님'} · 별도 계약 조건, 이번 적용에서 제외</dd></dl>}
          <button className="primary" disabled={!cycle || !release || detail.loading} onClick={showPreview}>적용 미리보기</button>
        </>}
      </fieldset>
      <ReadState value={preview} />
      {current && <section className="lifecycle-step" aria-label="공개 일정 적용 미리보기"><h3>3. 변경 전후 확인</h3><p><strong>{current.product.name} {current.product.version}</strong> ← {slug} / {cycle}</p>
        <div className="table-wrap"><table><thead><tr><th>항목</th><th>현재 값</th><th>선택한 공개 값</th></tr></thead><tbody><tr><td>보안지원 종료일</td><td>{current.before.security_end_date || '미확인'}</td><td>{current.after.security_end_date || '날짜 미확정'}</td></tr><tr><td>지원 근거 URL</td><td>{safeLink(current.before.lifecycle_source_url)}</td><td>{safeLink(current.after.lifecycle_source_url)}</td></tr></tbody></table></div>
        <p>수동 입력 시각: {time(current.product.manual_updated_at || current.before.verified_at)}. 공개 공지를 확인한 시각을 뜻하지 않습니다.</p><ul>{current.notes?.map((note) => <li key={note}>{note}</li>)}</ul>
        {!current.can_apply && <p role="alert" className="form-error">{current.blocked_reason}</p>}
        {isAdmin && <button className="primary" disabled={busy || !current.can_apply} onClick={apply}>이 제품에 공개 종료일 적용</button>}
      </section>}
      <section className="lifecycle-step" aria-label="공개 일정 적용 이력"><h3>이 제품의 공개 일정 적용 이력</h3><ReadState value={history} />
        {!history.loading && !history.error && !historyPage.items.length && <p>공개 일정 적용 이력이 없습니다.</p>}
        {historyPage.items.map((item) => <details key={item.id} className="lifecycle-history"><summary>{time(item.applied_at)} · {item.product_slug} / {item.release_cycle} · {item.applied_values.security_end_date || '날짜 없음'}</summary><dl><dt>보안지원 종료일 변경</dt><dd>{item.previous_values.security_end_date || '미확인'} → {item.applied_values.security_end_date || '미확인'}</dd><dt>적용 사용자</dt><dd>{item.applied_by_id ? `사용자 #${item.applied_by_id}` : '계정 미기록'}</dd><dt>원본 수집 시각</dt><dd>{time(item.fetched_at)}</dd><dt>제공처 생성 / 변경</dt><dd>{time(item.provider_generated_at)} / {time(item.provider_last_modified)}</dd><dt>데이터 출처</dt><dd>{safeLink(item.source_url)}</dd><dt>공식 정책</dt><dd>{safeLink(item.policy_url)}</dd><dt>보존된 원본 SHA-256</dt><dd><code>{item.source_sha256}</code></dd></dl></details>)}
        <Pages total={historyPage.total} offset={historyOffset} limit={10} loading={history.loading} name="적용 이력" onChange={setHistoryOffset} />
      </section>
    </>}
  </section>
}
