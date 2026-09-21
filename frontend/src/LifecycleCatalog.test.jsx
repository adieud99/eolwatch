import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import LifecycleCatalog from './LifecycleCatalog'

const product = { id: 1, name: 'Private Product', version: '16.4', vendor: 'Internal', security_end_date: '2027-01-01', lifecycle_source_url: 'https://example.test/manual', manual_updated_at: '2026-01-01T00:00:00Z' }
const cache = { available: true, stale: false, fetched_at: '2026-09-16T01:00:00Z', last_checked_at: '2026-09-16T01:00:00Z', provider_generated_at: '2026-09-15T00:00:00Z', source_url: 'https://endoflife.date/api/v1/products/postgresql/', content_sha256: 'a'.repeat(64), last_error: null }
const release = { name: '16', label: '16', isEol: false, eolFrom: '2028-11-09', eoasFrom: '2027-01-01', eoesFrom: '2035-01-01' }
const proposal = { product, release, cache, product_slug: 'postgresql', release_cycle: '16', expected_product_revision: 'b'.repeat(64), expected_catalog_sha256: cache.content_sha256, before: { security_end_date: product.security_end_date, lifecycle_source_url: product.lifecycle_source_url }, after: { security_end_date: release.eolFrom, lifecycle_source_url: 'https://www.postgresql.org/support/versioning/' }, can_apply: true, blocked_reason: null, notes: ['개별 구성요소 날짜는 유지합니다.'] }
const page = (items, total = items.length) => ({ items, total, limit: 20, offset: 0 })
function response(path) {
  if (path.startsWith('/lifecycle-catalog/local-products?')) return page([product])
  if (path.startsWith('/lifecycle-catalog/products?')) return { ...page([{ name: 'postgresql', label: 'PostgreSQL', category: 'database' }]), cache }
  if (path === '/lifecycle-catalog/products/postgresql') return { product: { name: 'postgresql', links: { releasePolicy: 'https://www.postgresql.org/support/versioning/' } }, releases: [release], cache }
  if (path.startsWith('/lifecycle-catalog/preview/')) return proposal
  if (path.startsWith('/lifecycle-catalog/applications?')) return page([])
  return { cache }
}
function setup(extra = {}) {
  const props = { api: vi.fn(async (path) => response(path)), onError: vi.fn(), onRefresh: vi.fn(), isAdmin: true, ...extra }
  return { ...render(<LifecycleCatalog {...props} />), props }
}
async function select() {
  fireEvent.click(await screen.findByRole('button', { name: 'Private Product 16.4 일정 연결' }))
  fireEvent.change(await screen.findByLabelText('공개 제품', { exact: true }), { target: { value: 'postgresql' } })
  await screen.findByRole('option', { name: '16', exact: true })
  fireEvent.change(screen.getByLabelText('지원 주기', { exact: true }), { target: { value: '16' } })
}
async function preview() {
  await select()
  fireEvent.click(screen.getByRole('button', { name: '적용 미리보기', exact: true }))
  return screen.findByRole('region', { name: '공개 일정 적용 미리보기' })
}
afterEach(cleanup)

describe('공개 지원 일정 연결', () => {
  it('명시적으로 제품·주기를 선택하고 변경 전후 확인 후 SHA와 제품 revision으로 적용한다', async () => {
    const { props } = setup()
    const previewRegion = await preview()
    expect(within(previewRegion).getByText('2028-11-09')).toBeInTheDocument()
    expect(screen.getByText(/2035-01-01.*별도 계약 조건/)).toBeInTheDocument()
    expect(props.api.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: '이 제품에 공개 종료일 적용' }))
    await waitFor(() => expect(props.onRefresh).toHaveBeenCalledTimes(1))
    const [, options] = props.api.mock.calls.find(([path]) => path === '/lifecycle-catalog/apply')
    expect(JSON.parse(options.body)).toEqual({ product_id: 1, product_slug: 'postgresql', release_cycle: '16', expected_product_revision: proposal.expected_product_revision, expected_catalog_sha256: proposal.expected_catalog_sha256 })
    await waitFor(() => expect(props.api.mock.calls.filter(([path]) => path.includes('/applications?')).length).toBeGreaterThan(1))
    expect(screen.queryByRole('region', { name: '공개 일정 적용 미리보기' })).not.toBeInTheDocument()
  })

  it('초기 제품 이름으로 공개 제품을 자동 추정하거나 외부 조회를 시작하지 않는다', async () => {
    const { props } = setup()
    fireEvent.click(await screen.findByRole('button', { name: 'Private Product 16.4 일정 연결' }))
    expect(screen.getByLabelText('공개 제품', { exact: true })).toHaveValue('')
    expect(props.api.mock.calls.some(([, options]) => options?.method)).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: '공개 제품 목록 갱신' }))
    await waitFor(() => expect(props.api.mock.calls.some(([path, options]) => path === '/lifecycle-catalog/refresh' && JSON.parse(options.body).product_slug === null)).toBe(true))
  })

  it('등록 제품 검색과 페이지를 서버에서 조회하고 취소된 응답을 폐기한다', async () => {
    let resolveOld, oldSignal
    const api = vi.fn((path, options) => {
      if (path.includes('/local-products?')) {
        if (path.includes('q=old')) { oldSignal = options.signal; return new Promise((resolve) => { resolveOld = resolve }) }
        return Promise.resolve(page([{ ...product, name: path.includes('q=new') ? 'New Product' : 'Private Product' }], 45))
      }
      return Promise.resolve(response(path))
    })
    setup({ api })
    await screen.findByText('Private Product')
    fireEvent.click(screen.getByRole('button', { name: '등록 제품 다음 페이지' }))
    await waitFor(() => expect(api.mock.calls.some(([path]) => path.endsWith('offset=20'))).toBe(true))
    fireEvent.change(screen.getByLabelText('등록 제품 검색', { selector: 'input' }), { target: { value: 'old' } })
    fireEvent.click(screen.getByRole('button', { name: '등록 제품 검색', exact: true }))
    await waitFor(() => expect(resolveOld).toBeDefined())
    fireEvent.change(screen.getByLabelText('등록 제품 검색', { selector: 'input' }), { target: { value: 'new' } })
    fireEvent.click(screen.getByRole('button', { name: '등록 제품 검색', exact: true }))
    await screen.findByText('New Product')
    expect(oldSignal.aborted).toBe(true)
    await act(async () => resolveOld(page([{ ...product, name: 'Stale Product' }])))
    expect(screen.queryByText('Stale Product')).not.toBeInTheDocument()
  })

  it('종료일 미확정은 종료 여부와 함께 표시하고 적용을 막는다', async () => {
    setup({ api: vi.fn(async (path) => path.startsWith('/lifecycle-catalog/preview/') ? { ...proposal, release: { ...release, isEol: true, eolFrom: null }, after: { ...proposal.after, security_end_date: null }, can_apply: false, blocked_reason: '종료일이 확정되지 않아 적용할 수 없습니다.' } : response(path)) })
    const region = await preview()
    expect(within(region).getByText('날짜 미확정')).toBeInTheDocument()
    expect(within(region).getByRole('button', { name: '이 제품에 공개 종료일 적용' })).toBeDisabled()
    expect(screen.getByText('종료일이 확정되지 않아 적용할 수 없습니다.')).toBeInTheDocument()
  })

  it('조회자는 저장된 자료·미리보기·이력만 읽는다', async () => {
    const { props } = setup({ isAdmin: false })
    await preview()
    expect(screen.queryByRole('button', { name: '공개 제품 목록 갱신' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '공개 일정 조회' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '이 제품에 공개 종료일 적용' })).not.toBeInTheDocument()
    expect(props.api.mock.calls.every(([, options]) => !options?.method)).toBe(true)
  })

  it('중복 적용 클릭을 막고 변경 충돌은 재비교하도록 이전 preview를 닫는다', async () => {
    let reject
    const api = vi.fn((path) => path.endsWith('/apply') ? new Promise((_resolve, failure) => { reject = failure }) : Promise.resolve(response(path)))
    const { props } = setup({ api })
    await preview()
    const button = screen.getByRole('button', { name: '이 제품에 공개 종료일 적용' })
    fireEvent.click(button); fireEvent.click(button)
    expect(api.mock.calls.filter(([path]) => path.endsWith('/apply'))).toHaveLength(1)
    await act(async () => reject(new Error('미리보기 이후 제품이 변경됐습니다. 다시 비교하세요.')))
    expect(await screen.findByText(/미리보기 이후 제품이 변경/)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '공개 일정 적용 미리보기' })).not.toBeInTheDocument()
    expect(props.onRefresh).not.toHaveBeenCalled()
  })

  it('공개 조회 실패 뒤 캐시 근거와 이전 날짜를 계속 표시한다', async () => {
    let failed = false
    const api = vi.fn(async (path) => {
      if (path.endsWith('/refresh')) { failed = true; throw new Error('공개 제공처 조회 실패(HTTP 429)') }
      if (path === '/lifecycle-catalog/products/postgresql' && failed) return { ...response(path), cache: { ...cache, last_error: '이전 자료를 유지합니다.', last_error_at: '2026-09-16T02:00:00Z' } }
      return response(path)
    })
    setup({ api })
    await select()
    fireEvent.click(screen.getByRole('button', { name: '공개 일정 조회' }))
    expect(await screen.findByText(/공개 제공처 조회 실패/)).toBeInTheDocument()
    expect(await screen.findByText(/이전 자료를 유지합니다/)).toBeInTheDocument()
    expect(screen.getByText(/2028-11-09.*제공처에서 미종료/)).toBeInTheDocument()
  })

  it('연결 대상 변경 후 이전 제품의 지연 미리보기를 표시하지 않는다', async () => {
    let resolvePreview, previewSignal
    const api = vi.fn((path, options) => {
      if (path.startsWith('/lifecycle-catalog/local-products?')) return Promise.resolve(page([product, { ...product, id: 2, name: 'Other Product' }]))
      if (path.startsWith('/lifecycle-catalog/preview/')) { previewSignal = options.signal; return new Promise((resolve) => { resolvePreview = resolve }) }
      return Promise.resolve(response(path))
    })
    setup({ api })
    await select()
    fireEvent.click(screen.getByRole('button', { name: '적용 미리보기' }))
    await waitFor(() => expect(resolvePreview).toBeDefined())
    fireEvent.click(screen.getByRole('button', { name: 'Other Product 16.4 일정 연결' }))
    expect(previewSignal.aborted).toBe(true)
    await act(async () => resolvePreview(proposal))
    expect(screen.queryByRole('region', { name: '공개 일정 적용 미리보기' })).not.toBeInTheDocument()
  })

  it('같은 공개 자료에서 지원 주기를 바꾸면 기존 비교 결과로 적용할 수 없다', async () => {
    let resolvePreview
    const api = vi.fn((path) => {
      if (path === '/lifecycle-catalog/products/postgresql') return Promise.resolve({ ...response(path), releases: [release, { ...release, name: '17', label: '17' }] })
      if (path.startsWith('/lifecycle-catalog/preview/')) return new Promise((resolve) => { resolvePreview = resolve })
      return Promise.resolve(response(path))
    })
    setup({ api })
    await select()
    fireEvent.click(screen.getByRole('button', { name: '적용 미리보기' }))
    await waitFor(() => expect(resolvePreview).toBeDefined())
    fireEvent.change(screen.getByLabelText('지원 주기', { exact: true }), { target: { value: '17' } })
    await act(async () => resolvePreview(proposal))
    expect(screen.queryByRole('button', { name: '이 제품에 공개 종료일 적용' })).not.toBeInTheDocument()
    expect(api.mock.calls.some(([path]) => path.endsWith('/apply'))).toBe(false)
  })
})
