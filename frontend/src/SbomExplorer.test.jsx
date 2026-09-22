import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import SbomExplorer from './SbomExplorer'

afterEach(cleanup)
const item = { id: 2, name: 'jinja2', version: '3.1.4', bom_ref: 'pkg2', purl: 'pkg:pypi/jinja2@3.1.4', supplier: 'Pallets', licenses: ['BSD-3-Clause'], hashes: [] }
const metadata = { id: 12, serial_number: 'urn:sbom:12', component_count: 52, dependency_count: 2, quality_score: 90, quality_details: { checks: { component_names: true, license_information: false } }, asset: { asset_tag: 'APP-1', name: '주문 서비스' } }
function open(overrides = {}) {
  const request = vi.fn(async (path) => path.endsWith('/detail') ? metadata : path.includes('/components/') ? item : { items: [item], total: 52 })
  const props = { sbomId: 12, request, download: vi.fn(async () => {}), onChanged: vi.fn(), onClose: vi.fn(), onViewCve: vi.fn(), ...overrides }
  return { ...render(<SbomExplorer {...props} />), props }
}

describe('SBOM 상세', () => {
  it('메타데이터·품질과 라이선스를 보여주고 서버 페이지 검색을 사용한다', async () => {
    const { props } = open()
    await screen.findByRole('button', { name: 'jinja2 3.1.4 상세 보기' })
    expect(screen.getByText('BSD-3-Clause')).toBeInTheDocument()
    expect(screen.getByText('라이선스')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '구성요소 다음 페이지' }))
    await waitFor(() => expect(props.request).toHaveBeenCalledWith('/sboms/12/component-page?q=&limit=50&offset=50', expect.anything()))
    fireEvent.change(screen.getByLabelText('구성요소 검색'), { target: { value: 'pkg:pypi/jinja2' } })
    fireEvent.click(screen.getByRole('button', { name: '검색', exact: true }))
    await waitFor(() => expect(props.request).toHaveBeenCalledWith('/sboms/12/component-page?q=pkg%3Apypi%2Fjinja2&limit=50&offset=0', expect.anything()))
  })


  it('메타데이터와 원본·CVE 이동을 제공한다', async () => {
    const { props } = open()
    fireEvent.click(await screen.findByRole('button', { name: 'jinja2 3.1.4 상세 보기' }))
    await screen.findByRole('region', { name: '구성요소 상세' })
    fireEvent.click(screen.getByRole('button', { name: '이 SBOM의 CVE 보기' }))
    expect(props.onViewCve).toHaveBeenCalledWith(12)
    fireEvent.click(screen.getByRole('button', { name: 'SBOM 원본 JSON' }))
    await waitFor(() => expect(props.download).toHaveBeenCalledWith('/sboms/12/raw', 'eolwatch-sbom-12.json', expect.any(AbortSignal)))
  })

  it('검색을 바꾸면 오래된 결과를 버린다', async () => {
    let oldResult
    const request = vi.fn((path) => path.endsWith('/detail') ? Promise.resolve(metadata) : path.includes('q=new') ? Promise.resolve({ items: [{ ...item, name: 'new-package' }], total: 1 }) : new Promise((done) => { oldResult = done }))
    open({ request })
    fireEvent.change(screen.getByLabelText('구성요소 검색'), { target: { value: 'new' } })
    fireEvent.click(screen.getByRole('button', { name: '검색', exact: true }))
    await screen.findByText('new-package')
    await act(async () => oldResult({ items: [{ ...item, name: 'stale-package' }], total: 1 }))
    expect(screen.queryByText('stale-package')).not.toBeInTheDocument()
  })
})
