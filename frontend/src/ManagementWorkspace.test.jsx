import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ManagementWorkspace from './ManagementWorkspace'

const product = { id: 7, name: 'Jinja2', version: '3.1.6', product_type: 'LIBRARY', vendor: 'Pallets', eol_date: null, support_end_date: null, security_end_date: null, lifecycle_source_url: null, risk_level: 'UNKNOWN', purl: 'pkg:pypi/jinja2@3.1.6' }
const contract = { id: 9, customer_id: 1, customer_name: '고객사 A', contract_no: 'MA-2026-01', provider: '지원 업체', start_date: '2026-01-01', end_date: '2026-12-31', annual_cost: 120000, service_level: '24x7', asset_ids: [1], risk_level: 'WARN' }
const assets = [{ id: 1, asset_tag: 'VM-A', name: '서버 A', site_id: 1 }, { id: 2, asset_tag: 'VM-B', name: '서버 B', site_id: 2 }]
const customers = [{ id: 1, name: '고객사 A' }, { id: 2, name: '고객사 B' }]
const sites = [{ id: 1, customer_id: 1, name: '서울' }, { id: 2, customer_id: 2, name: '부산' }]
const impact = { asset_count: 1, affected_assets: [{ ...assets[0], ip_address: '10.0.0.1' }] }
const response = (path) => path.endsWith('/impact') ? impact : path === '/products/7' ? product : path.startsWith('/products?') ? [product] : path === '/contracts/9' ? contract : [contract]
function open(extra = {}) {
  const props = { assets, customers, sites, canEdit: true, request: vi.fn(async (path) => response(path)), onChanged: vi.fn(), onViewAsset: vi.fn(), ...extra }
  return { ...render(<ManagementWorkspace {...props} />), props }
}
async function productDetails() { fireEvent.click(await screen.findByRole('button', { name: '제품 상세' })); await screen.findByLabelText('공식 근거 URL') }
afterEach(cleanup)

describe('제품 수명주기 관리', () => {
  it('날짜 근거를 실제 제품에 저장하고 영향 자산으로 이동한다', async () => {
    const { props } = open()
    await productDetails()
    fireEvent.change(screen.getByLabelText('보안지원 종료일'), { target: { value: '2027-03-31' } })
    fireEvent.click(screen.getByRole('button', { name: '제품 날짜 저장' }))
    await screen.findByText('수명주기 날짜에는 공식 근거 URL을 입력하세요.')
    expect(props.request.mock.calls.some(([, options]) => options?.method)).toBe(false)
    fireEvent.change(screen.getByLabelText('공식 근거 URL'), { target: { value: 'https://example.com/jinja' } })
    fireEvent.click(screen.getByRole('button', { name: '자산 보기' }))
    expect(props.onViewAsset).toHaveBeenCalledWith(1)
    fireEvent.click(screen.getByRole('button', { name: '제품 날짜 저장' }))
    await waitFor(() => expect(props.onChanged).toHaveBeenCalledWith('제품 수명주기 정보를 저장했습니다.'))
    const [path, options] = props.request.mock.calls.find(([, options]) => options?.method === 'PATCH')
    expect(path).toBe('/products/7')
    expect(JSON.parse(options.body)).toEqual({ security_end_date: '2027-03-31', lifecycle_source_url: 'https://example.com/jinja' })
  })

  it('SQL 페이지 검색 파라미터를 보내며 이전 조회 응답은 폐기한다', async () => {
    let stale, staleSignal
    const request = vi.fn((path, options) => {
      if (path.includes('q=old')) { staleSignal = options.signal; return new Promise((resolve) => { stale = resolve }) }
      return Promise.resolve(path.includes('q=new') ? [{ ...product, name: '새 제품' }] : Array.from({ length: 21 }, (_, i) => ({ ...product, id: i + 1, name: `제품 ${i}` })))
    })
    open({ request })
    await screen.findByText('제품 19')
    expect(screen.queryByText('제품 20')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '다음 페이지' }))
    await waitFor(() => expect(request.mock.calls.some(([path]) => path.includes('offset=20'))).toBe(true))
    fireEvent.change(screen.getByLabelText('제품 검색어'), { target: { value: 'old' } })
    fireEvent.click(screen.getByRole('button', { name: '검색', exact: true }))
    await waitFor(() => expect(stale).toBeDefined())
    fireEvent.change(screen.getByLabelText('제품 검색어'), { target: { value: 'new' } })
    fireEvent.click(screen.getByRole('button', { name: '검색', exact: true }))
    await screen.findByText('새 제품')
    expect(staleSignal.aborted).toBe(true)
    await act(async () => stale([{ ...product, name: '오래된 제품' }]))
    expect(screen.queryByText('오래된 제품')).not.toBeInTheDocument()
    expect(request.mock.calls.some(([path]) => path.includes('limit=21&offset=0&q=new'))).toBe(true)
  })

  it('저장 오류 후 입력을 유지하고 재시도하며 중복 클릭을 막는다', async () => {
    let finish, attempts = 0
    const request = vi.fn((path, options) => {
      if (options?.method === 'PATCH') { if (++attempts === 1) return Promise.reject(new Error('권한이 변경되었습니다')); return new Promise((resolve) => { finish = resolve }) }
      return Promise.resolve(response(path))
    })
    const { props } = open({ request })
    await productDetails()
    fireEvent.change(screen.getByLabelText('공식 근거 URL'), { target: { value: 'https://example.com/source' } })
    fireEvent.click(screen.getByRole('button', { name: '제품 날짜 저장' }))
    await screen.findByText(/권한이 변경되었습니다/)
    expect(screen.getByLabelText('공식 근거 URL')).toHaveValue('https://example.com/source')
    const button = screen.getByRole('button', { name: '제품 날짜 저장' })
    fireEvent.click(button); fireEvent.click(button)
    expect(attempts).toBe(2)
    await act(async () => finish(product))
    expect(props.onChanged).toHaveBeenCalledTimes(1)
  })

  it('조회자는 근거와 영향 자산을 읽고 제품과 계약 편집은 할 수 없다', async () => {
    open({ canEdit: false })
    fireEvent.click(await screen.findByRole('button', { name: '제품 상세' }))
    await screen.findByText('pkg:pypi/jinja2@3.1.6')
    expect(screen.queryByRole('button', { name: '제품 날짜 저장' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: '유지보수 계약' }))
    expect(screen.queryByRole('button', { name: '계약 등록', exact: true })).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: '계약 상세' }))
    await screen.findByText('24x7')
    expect(screen.queryByRole('button', { name: '계약 변경 저장' })).not.toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '계약 상세' })).getByText('VM-A')).toBeInTheDocument()
  })
})

describe('유지보수 계약 관리', () => {
  it('신규 계약의 기간과 소속을 확인하고 연결 자산을 함께 등록한다', async () => {
    const { props } = open()
    fireEvent.click(screen.getByRole('tab', { name: '유지보수 계약' }))
    fireEvent.click(screen.getByRole('button', { name: '계약 등록', exact: true }))
    fireEvent.change(screen.getByLabelText('계약 고객사'), { target: { value: '1' } })
    expect(screen.queryByLabelText('VM-B · 서버 B')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('계약번호'), { target: { value: 'MA-NEW' } })
    fireEvent.change(screen.getByLabelText('유지보수사'), { target: { value: '새 지원사' } })
    fireEvent.change(screen.getByLabelText('계약 시작일'), { target: { value: '2026-09-15' } })
    fireEvent.change(screen.getByLabelText('계약 종료일'), { target: { value: '2026-01-01' } })
    fireEvent.click(screen.getByRole('button', { name: '계약 등록 저장' }))
    await screen.findByText('계약 종료일은 시작일보다 빠를 수 없습니다.')
    fireEvent.change(screen.getByLabelText('계약 종료일'), { target: { value: '2027-09-14' } })
    fireEvent.click(screen.getByLabelText('VM-A · 서버 A'))
    fireEvent.click(screen.getByRole('button', { name: '계약 등록 저장' }))
    await waitFor(() => expect(props.onChanged).toHaveBeenCalledWith('계약을 등록했습니다.'))
    const [path, options] = props.request.mock.calls.find(([, options]) => options?.method === 'POST')
    expect(path).toBe('/contracts')
    expect(JSON.parse(options.body)).toEqual({ customer_id: 1, contract_no: 'MA-NEW', provider: '새 지원사', start_date: '2026-09-15', end_date: '2027-09-14', annual_cost: null, service_level: null, asset_ids: [1] })
  })

  it('기존 계약은 단건 최신 조회 후 변경한 항목만 PATCH하며 고객사 변경의 기존 자산을 몰래 지우지 않는다', async () => {
    const { props } = open()
    fireEvent.click(screen.getByRole('tab', { name: '유지보수 계약' }))
    fireEvent.click(await screen.findByRole('button', { name: '계약 상세' }))
    await waitFor(() => expect(screen.getByLabelText('유지보수사')).toHaveValue('지원 업체'))
    fireEvent.change(screen.getByLabelText('계약 고객사'), { target: { value: '2' } })
    expect(screen.getByLabelText(/VM-A.*고객사 불일치/)).toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: '계약 변경 저장' }))
    await screen.findByText('계약 자산은 선택한 고객사의 사이트에 연결되어 있어야 합니다.')
    fireEvent.click(screen.getByLabelText(/VM-A.*고객사 불일치/))
    fireEvent.click(screen.getByLabelText('VM-B · 서버 B'))
    fireEvent.click(screen.getByRole('button', { name: '계약 변경 저장' }))
    await waitFor(() => expect(props.onChanged).toHaveBeenCalledWith('계약 변경을 저장했습니다.'))
    const [path, options] = props.request.mock.calls.find(([, options]) => options?.method === 'PATCH')
    expect(path).toBe('/contracts/9')
    expect(JSON.parse(options.body)).toEqual({ customer_id: 2, asset_ids: [2] })
  })
})
