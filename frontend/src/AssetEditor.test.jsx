import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import AssetEditor from './AssetEditor'

const asset = { id: 1, asset_tag: 'LAB-01', name: '서버', asset_type: 'vm', site_id: 1, model_release_id: null, ssh_port: 22, monitored: true, ip_address: '10.0.0.1', ssh_username: 'collector', support_end_date: null, lifecycle_source_url: null }
const sites = [{ id: 1, name: '서울', customer_name: '고객', customer_id: 1 }, { id: 2, name: '부산', customer_name: '고객', customer_id: 1 }]
const models = [{ id: 8, name: 'R750', version: '1', vendor: 'Dell' }]
function open(extra = {}) {
  const props = { asset, sites, canEdit: true, request: vi.fn(async (path, options) => options?.method === 'PATCH' ? { ...asset, ...JSON.parse(options.body) } : path.startsWith('/products') ? models : asset), onSaved: vi.fn(), onClose: vi.fn(), ...extra }
  return { ...render(<AssetEditor {...props} />), props }
}
const ready = async () => waitFor(() => expect(screen.getByRole('button', { name: '자산 변경 저장' })).toBeEnabled())
afterEach(cleanup)

describe('자산 수정', () => {
  it('최신 정보 조회 후 연결 필드와 날짜 근거를 변경하고 변경한 값만 저장한다', async () => {
    const { props } = open()
    expect(screen.getByRole('button', { name: '자산 변경 저장' })).toBeDisabled()
    await ready()
    fireEvent.change(screen.getByLabelText('SSH 포트'), { target: { value: '2222' } })
    fireEvent.change(screen.getByLabelText('고객사 / 사이트'), { target: { value: '2' } })
    fireEvent.change(screen.getByLabelText('장비 모델 연결'), { target: { value: '8' } })
    fireEvent.change(screen.getByLabelText('지원종료일'), { target: { value: '2027-01-01' } })
    fireEvent.change(screen.getByLabelText('수명주기 근거 URL'), { target: { value: 'https://example.com/support' } })
    fireEvent.click(screen.getByRole('button', { name: '자산 변경 저장' }))
    await waitFor(() => expect(props.onSaved).toHaveBeenCalled())
    const [, options] = props.request.mock.calls.find(([, options]) => options?.method === 'PATCH')
    expect(JSON.parse(options.body)).toEqual({ ssh_port: 2222, site_id: 2, model_release_id: 8, support_end_date: '2027-01-01', lifecycle_source_url: 'https://example.com/support' })
    expect(options.headers['Content-Type']).toBe('application/json')
  })

  it('조회 실패 시 오래된 자산 값으로 저장하지 못하고 재조회한 현재 값을 보여준다', async () => {
    let calls = 0
    const request = vi.fn(async (path) => { if (path.startsWith('/products')) return []; if (++calls === 1) throw new Error('연결 실패'); return { ...asset, ssh_port: 2200 } })
    open({ request })
    await screen.findByText(/자산 정보를 불러오지 못했습니다/)
    expect(screen.getByRole('button', { name: '자산 변경 저장' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '자산 정보 다시 불러오기' }))
    await ready()
    expect(screen.getByLabelText('SSH 포트')).toHaveValue(2200)
  })

  it('삭제 확인 태그가 일치할 때만 요청하며 이력 보존 거부를 표시한다', async () => {
    const request = vi.fn(async (path, options) => { if (options?.method === 'DELETE') throw new Error('분석 이력이 있는 자산은 삭제할 수 없습니다'); return path.startsWith('/products') ? models : asset })
    const { props } = open({ request })
    await ready()
    fireEvent.click(screen.getByRole('button', { name: '자산 삭제…' }))
    expect(request.mock.calls.some(([, options]) => options?.method === 'DELETE')).toBe(false)
    const remove = screen.getByRole('button', { name: '자산 영구 삭제' })
    expect(remove).toBeDisabled()
    fireEvent.change(screen.getByLabelText('삭제 확인 자산번호'), { target: { value: 'LAB-01' } })
    fireEvent.click(remove)
    await screen.findByText(/분석 이력이 있는 자산은 삭제할 수 없습니다/)
    expect(props.onSaved).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '삭제 취소' }))
    expect(screen.getByLabelText('IP 주소 / 호스트')).toHaveValue('10.0.0.1')
  })

  it('중복 저장을 막고 언마운트 후 응답을 폐기한다', async () => {
    let resolve
    const request = vi.fn((path, options) => options?.method === 'PATCH' ? new Promise((done) => { resolve = done }) : Promise.resolve(path.startsWith('/products') ? models : asset))
    const { props, unmount } = open({ request })
    await ready()
    const submit = screen.getByRole('button', { name: '자산 변경 저장' })
    fireEvent.click(submit); fireEvent.click(submit)
    const writes = request.mock.calls.filter(([, options]) => options?.method === 'PATCH')
    expect(writes).toHaveLength(1)
    unmount()
    expect(writes[0][1].signal.aborted).toBe(true)
    await act(async () => resolve(asset))
    expect(props.onSaved).not.toHaveBeenCalled()
  })

  it('조회자에게 연결 정보를 보여주되 수정과 삭제는 숨긴다', async () => {
    const { props } = open({ canEdit: false })
    await screen.findByText('10.0.0.1')
    expect(screen.queryByRole('button', { name: '자산 변경 저장' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '자산 삭제…' })).not.toBeInTheDocument()
    expect(props.request.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })
})
