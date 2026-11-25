#!/usr/bin/env node
/**
 * 出站守卫（CLA-1，utils/outboundGuard.js）负向 + 正向回归测试。
 *
 * 覆盖（对应 artifacts/coordinator-review-pending.md 的复核项）：
 *   1) http.request 必须原样携带 pathname + query（真实本地 HTTP 服务回显校验）；
 *   2) 固定 lookup 兼容 Node 20+ 的 opts.all / autoSelectFamily 调用形态（真实 TCP 连接即证明）；
 *   3) 重定向逐跳重校验（真实服务 A 302 → 未放行的 127.0.0.2 → 拒绝）；
 *   4) 跨源跳转大小写无关地剥掉 Authorization/Cookie（真实服务捕获请求头）；
 *   5) 地址分类：私网 / 元数据 / IPv4 映射 IPv6 / NAT64 / 6to4 / Teredo / 混合答案 / 空答案；
 *   6) 白名单：精确主机/IP（可带端口），CIDR / 通配一律拒绝；
 *   7) 订阅默认守卫直连（fetchAndParseM3u 走真实本地 fixture 正常解析）；
 *   8) chunked 无 Content-Length 的响应体按实际字节数限流；
 *   9) 生产环境模块 fetchImpl 注入 fail closed；仅 CLA1_TEST_FETCH_INJECTION=1 不放行，
 *      须 NODE_ENV=test 且 CLA1_TEST_FETCH_INJECTION=1 同时成立才放行。
 *  10) 公共分发边界（fetchNested / pipeUpstream / probeUpstream）：未验证的 fetchMedia
 *      钩子（spy）在生产不被调用（含元数据地址），仅测试注入或 markGuardedTransport
 *      标记的守卫传输放行；默认守卫直连本地 fixture 回归。
 *
 * 全部离线：本地临时服务 + 注入的解析器/显式白名单（生产配置面 msafeLanAllow）。
 * 运行： node scripts/test-outbound-guard.mjs
 */
import assert from 'node:assert/strict'
import http from 'node:http'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const DATA_DIR = mkdtempSync(join(tmpdir(), 'iptv-outbound-guard-'))
process.env.mdataDir = DATA_DIR
// 受控本地服务经显式精确白名单放行（127.0.0.2 故意不放进名单，用于负向用例）
process.env.msafeLanAllow = '127.0.0.1,localhost,[::1]'

const {
  isForbiddenAddress, parseLanAllowlist, isAllowlistedUrl, resolveAndValidateTarget,
  safeFetchDirect, readCappedBody, MAX_SUBSCRIPTION_BODY_BYTES, OutboundDeniedError,
} = await import('../utils/outboundGuard.js')
const { fetchUpstreamResponse, fetchNested, pipeUpstream, probeUpstream, markGuardedTransport } = await import('../utils/hlsProxy.js')
const { fetchAndParseM3u, parsePlaylistContent } = await import('../utils/externalSources.js')
const { customSourceFetch } = await import('../utils/customSourceProxy.js')

let passed = 0
const check = async (name, fn) => { await fn(); passed++; console.log('  ✅ ' + name) }

console.log('出站守卫测试（CLA-1）')

// ---- 本地受控服务 ----
const seen = []
const a = http.createServer((req, res) => {
  seen.push({ url: req.url, host: req.headers.host, ua: req.headers['user-agent'], auth: req.headers.authorization, cookie: req.headers.cookie })
  if (req.url.startsWith('/redirect-to-b')) { res.writeHead(302, { Location: `http://127.0.0.2:${bPort}/target?x=1` }); res.end(); return }
  if (req.url.startsWith('/redirect-same')) { res.writeHead(302, { Location: '/landed?via=redirect' }); res.end(); return }
  if (req.url.startsWith('/chunked-overflow')) {
    // chunked、无 Content-Length：发 1 MB 就够触发 readCappedBody 的按字节限流（上限用 64 KB 注入）
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' })
    const chunk = Buffer.alloc(64 * 1024, 0x61)
    let sent = 0
    const timer = setInterval(() => { if (sent >= 1024 * 1024) { clearInterval(timer); res.end(); return } res.write(chunk); sent += chunk.length }, 1)
    res.on('close', () => clearInterval(timer))
    return
  }
  if (req.url.startsWith('/m3u')) {
    res.writeHead(200, { 'Content-Type': 'audio/x-mpegurl' })
    res.end('#EXTM3U\n#EXTINF:-1 group-title="测试",守卫台\nhttp://cdn.example/live/a.m3u8\n')
    return
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' })
  res.end(`ok:${req.url}`)
})
await new Promise(r => a.listen(0, '127.0.0.1', r))
const aPort = a.address().port

const bSeen = []
const b = http.createServer((req, res) => {
  bSeen.push({ auth: req.headers.authorization, cookie: req.headers.cookie })
  res.writeHead(200, { 'Content-Type': 'text/plain' })
  res.end('b-target')
})
await new Promise(r => b.listen(0, '127.0.0.2', r))
const bPort = b.address().port

const BASE = `http://127.0.0.1:${aPort}`

try {
  // ---- 地址分类 ----
  await check('地址分类：私网/回环/元数据/映射 IPv6/NAT64/6to4/Teredo 全拒；公网放行', () => {
    for (const ip of ['10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.255', '192.168.1.1',
      '127.0.0.1', '127.8.8.8', '169.254.169.254', '169.254.1.1', '100.64.0.1', '100.127.255.255',
      '198.18.0.5', '198.19.255.255', '192.0.0.9', '192.0.2.1', '192.88.99.1', '198.51.100.7',
      '203.0.113.7', '224.0.0.1', '240.0.0.1', '0.0.0.0', '255.255.255.255',
      '::1', '::', '::ffff:8.8.8.8', '::ffff:127.0.0.1', '::ffff:0:8.8.8.8', '64:ff9b::a00:1',
      '2002:0a00:0001::', '2001::1', '2001:db8::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'fec0::1', 'ff02::1']) {
      assert.equal(isForbiddenAddress(ip), true, ip)
    }
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '223.5.5.5', '2001:4860:4860::8888', '64:ff9b::808:808', '2002:5db8:d822::']) {
      assert.equal(isForbiddenAddress(ip), false, ip)
    }
  })

  // ---- 白名单解析 ----
  await check('白名单：只认精确主机/IP（可带 :端口）；CIDR、通配、非法条目忽略并报告', () => {
    const { entries, rejected } = parseLanAllowlist('192.168.1.5:8080, nas.lan, [::1]:90, 10.0.0.0/24, *.example.com, 192.168.1.*, bad..host, :99')
    assert.deepEqual(entries, [{ host: '192.168.1.5', port: '8080' }, { host: 'nas.lan', port: '' }, { host: '::1', port: '90' }])
    assert.equal(rejected.length, 5)
    assert.equal(isAllowlistedUrl('http://192.168.1.5:8080/a', entries), true)
    assert.equal(isAllowlistedUrl('http://192.168.1.5:9999/a', entries), false, '端口必须精确匹配')
    assert.equal(isAllowlistedUrl('http://192.168.1.6:8080/a', entries), false)
    assert.equal(isAllowlistedUrl('https://NAS.LAN:443/a', entries), true, '主机名大小写无关')
  })

  // ---- 解析校验（注入解析器，无真实 DNS）----
  const resolverOf = answers => async () => answers.map(([address, family]) => ({ address, family }))
  await check('解析校验：混合答案（公网+私网）、全私网、空答案、映射 IPv6 一律拒绝', async () => {
    const pub = [['93.184.216.34', 4]]
    await assert.rejects(resolveAndValidateTarget('http://x.example/a', { resolver: resolverOf([['93.184.216.34', 4], ['10.0.0.1', 4]]) }), /不是全球单播/)
    await assert.rejects(resolveAndValidateTarget('http://x.example/a', { resolver: resolverOf([['10.0.0.1', 4]]) }), /不是全球单播/)
    await assert.rejects(resolveAndValidateTarget('http://x.example/a', { resolver: resolverOf([['::ffff:8.8.8.8', 6]]) }), /不是全球单播/)
    await assert.rejects(resolveAndValidateTarget('http://x.example/a', { resolver: resolverOf([]) }), /没有可用的解析答案/)
    await assert.rejects(resolveAndValidateTarget('http://x.example/a', { resolver: async () => { throw new Error('ENOTFOUND') } }), /DNS 解析失败/)
    const ok = await resolveAndValidateTarget('http://x.example/a', { resolver: resolverOf(pub) })
    assert.deepEqual(ok.addresses, [{ address: '93.184.216.34', family: 4 }])
    // 白名单精确命中：跳过地址类别判定（仍固定解析答案）
    const lan = await resolveAndValidateTarget('http://10.1.1.9:8080/a', { allowlist: [{ host: '10.1.1.9', port: '8080' }] })
    assert.equal(lan.allowlisted, true)
  })

  // ---- 真实本地服务：路径+查询、请求头、重定向、大小写无关剥头 ----
  await check('真实连接：pathname+query 原样到达（http.request 不带 path 会打到根路径）', async () => {
    const res = await safeFetchDirect(`${BASE}/live/media.m3u8?token=abc&x=1`, { headers: { 'User-Agent': 'GuardUA/1.0' } })
    assert.equal(res.status, 200)
    assert.match(await res.text(), /ok:\/live\/media\.m3u8\?token=abc&x=1/)
    const hit = seen.at(-1)
    assert.equal(hit.url, '/live/media.m3u8?token=abc&x=1')
    assert.equal(hit.ua, 'GuardUA/1.0', '自定义请求头原样携带')
    assert.equal(hit.host, `127.0.0.1:${aPort}`)
  })

  await check('真实连接：跟随重定向且重定向目标逐跳重校验（未放行 127.0.0.2 被拒）', async () => {
    const ok = await safeFetchDirect(`${BASE}/redirect-same`)
    assert.equal(ok.status, 200)
    assert.equal(ok.url, `${BASE}/landed?via=redirect`)
    await assert.rejects(safeFetchDirect(`${BASE}/redirect-to-b`), error => {
      assert.ok(error instanceof OutboundDeniedError)
      assert.match(error.message, /127\.0\.0\.2/)
      return true
    })
  })

  await check('真实连接：跨源重定向大小写无关地剥掉 Authorization/Cookie', async () => {
    // 跨源 = 同主机不同端口（origin 含端口）。B 在同一回环主机上监听不同端口，仍在白名单内
    const b2Seen = []
    const b2 = http.createServer((req, res) => {
      b2Seen.push({ auth: req.headers.authorization, cookie: req.headers.cookie })
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('b2-target')
    })
    await new Promise(r => b2.listen(0, '127.0.0.1', r))
    const b2Port = b2.address().port
    const redirector = http.createServer((req, res) => { res.writeHead(302, { Location: `http://127.0.0.1:${b2Port}/target` }); res.end() })
    await new Promise(r => redirector.listen(0, '127.0.0.1', r))
    const rp = redirector.address().port
    try {
      const res = await safeFetchDirect(`http://127.0.0.1:${rp}/go`, {
        headers: { Authorization: 'Bearer secret', Cookie: 'sid=1', 'x-custom': 'keep' },
      })
      assert.equal(res.status, 200)
      assert.equal(await res.text(), 'b2-target')
      assert.equal(b2Seen[0].auth, undefined, 'Authorization 必须被剥掉（大小写无关）')
      assert.equal(b2Seen[0].cookie, undefined, 'Cookie 必须被剥掉（大小写无关）')
    } finally {
      redirector.closeAllConnections?.(); redirector.close()
      b2.closeAllConnections?.(); b2.close()
    }
  })

  // ---- 订阅默认守卫 + 响应体限流 ----
  await check('订阅默认守卫直连：真实本地 fixture 正常解析出频道', async () => {
    const channels = await fetchAndParseM3u(`${BASE}/m3u`)
    assert.equal(channels.length, 1)
    assert.equal(channels[0].name, '守卫台')
  })

  await check('readCappedBody：chunked 无 Content-Length 的响应按实际字节数限流并中止', async () => {
    const res = await safeFetchDirect(`${BASE}/chunked-overflow`)
    await assert.rejects(readCappedBody(res, 64 * 1024, '测试响应'), /超过上限/)
    // Content-Length 预检同样拦
    const decl = await safeFetchDirect(`${BASE}/chunked-overflow`)
    Object.defineProperty(decl.headers, 'get', { value: name => name === 'content-length' ? String(999 * 1024 * 1024) : null })
    await assert.rejects(readCappedBody(decl, 64 * 1024, '测试响应'), /超过上限/)
    // 小响应照常
    const small = await safeFetchDirect(`${BASE}/m3u`)
    const buf = await readCappedBody(small, MAX_SUBSCRIPTION_BODY_BYTES, '订阅')
    assert.ok(buf.toString('utf8').startsWith('#EXTM3U'))
  })

  // ---- 未放行目标一律拒绝 ----
  await check('未放行目标拒绝：字面 127.0.0.2 / 局域网主机名 / 内嵌凭据 / 非 http(s)', async () => {
    await assert.rejects(safeFetchDirect(`http://127.0.0.2:${bPort}/x`), /不在出站白名单/)
    await assert.rejects(safeFetchDirect('http://mybox.lan/x'), /局域网\/本机主机名/)
    await assert.rejects(safeFetchDirect('http://user:pass@example.com/x'), /内嵌账号密码/)
    await assert.rejects(safeFetchDirect('file:///etc/passwd'), /不支持的协议/)
    // HLS 上游静态校验同样生效
    await assert.rejects(fetchUpstreamResponse(`http://127.0.0.2:${bPort}/x`), /不在出站白名单/)
  })

  // ---- 模块 fetchImpl：生产 fail closed；显式测试注入放行 ----
  await check('HLS 上游模块 fetchImpl：生产（无注入环境变量）fail closed', async () => {
    await assert.rejects(
      fetchUpstreamResponse(`${BASE}/m3u`, { fetchImpl: (url, options) => safeFetchDirect(url, options) }),
      error => { assert.ok(error instanceof OutboundDeniedError); assert.match(error.message, /无法固定 DNS 连接/); return true },
    )
  })
  await check('HLS 上游模块 fetchImpl：仅 CLA1_TEST_FETCH_INJECTION=1（NODE_ENV 非 test）仍 fail closed', async () => {
    delete process.env.NODE_ENV
    process.env.CLA1_TEST_FETCH_INJECTION = '1'
    try {
      await assert.rejects(
        fetchUpstreamResponse(`${BASE}/m3u`, { fetchImpl: (url, options) => safeFetchDirect(url, options) }),
        error => { assert.ok(error instanceof OutboundDeniedError); assert.match(error.message, /无法固定 DNS 连接/); return true },
      )
    } finally {
      delete process.env.CLA1_TEST_FETCH_INJECTION
    }
  })
  await check('HLS 上游模块 fetchImpl：NODE_ENV=test 且 CLA1_TEST_FETCH_INJECTION=1 才放行', async () => {
    process.env.NODE_ENV = 'test'
    process.env.CLA1_TEST_FETCH_INJECTION = '1'
    try {
      const resp = await fetchUpstreamResponse(`${BASE}/m3u`, { fetchImpl: (url, options) => safeFetchDirect(url, options) })
      assert.equal(resp.status, 200)
      assert.match(await resp.text(), /#EXTM3U/)
    } finally {
      delete process.env.CLA1_TEST_FETCH_INJECTION
    }
  })

  // ---- 公共分发边界（审查项 10）：未经守卫的 fetchMedia 钩子在清单/分片/HEAD 共用边界 fail closed ----
  const MANIFEST = () => new Response('#EXTM3U\n#EXTINF:1,\nx\nhttp://x.example/x.ts\n', { headers: { 'content-type': 'application/vnd.apple.mpegurl' } })
  const stubRes = () => ({ headersSent: false, statusCode: 0, writeHead(code) { this.statusCode = code }, end() {}, on() {}, off() {}, destroy() {} })
  await check('fetchNested 边界：spy 钩子在正常生产环境不被调用（元数据地址也不放行，审查原命令形态）', async () => {
    delete process.env.NODE_ENV
    delete process.env.CLA1_TEST_FETCH_INJECTION
    let calls = 0
    const spy = async () => { calls++; return MANIFEST() }
    const nested = await fetchNested('http://169.254.169.254/latest/meta-data/', {}, undefined, spy)
    assert.equal(nested, null, '必须整体拒绝（调用方按取回失败处理）')
    assert.equal(calls, 0, 'spy 钩子一次都不能被调用')
  })
  await check('fetchNested 边界：仅 CLA1_TEST_FETCH_INJECTION=1（无 NODE_ENV=test）仍不放行', async () => {
    delete process.env.NODE_ENV
    process.env.CLA1_TEST_FETCH_INJECTION = '1'
    try {
      let calls = 0
      const spy = async () => { calls++; return MANIFEST() }
      assert.equal(await fetchNested('http://169.254.169.254/latest/meta-data/', {}, undefined, spy), null)
      assert.equal(calls, 0)
    } finally {
      delete process.env.CLA1_TEST_FETCH_INJECTION
    }
  })
  await check('fetchNested 边界：NODE_ENV=test + 标志才放行注入钩子（测试缝仍可用）', async () => {
    process.env.NODE_ENV = 'test'
    process.env.CLA1_TEST_FETCH_INJECTION = '1'
    try {
      let calls = 0
      const spy = async () => { calls++; return MANIFEST() }
      const nested = await fetchNested('http://media.example/x.m3u8', {}, undefined, spy)
      assert.ok(nested && nested.text.startsWith('#EXTM3U'))
      assert.equal(calls, 1)
    } finally {
      delete process.env.NODE_ENV
      delete process.env.CLA1_TEST_FETCH_INJECTION
    }
  })
  await check('pipeUpstream 边界：spy 钩子不被调用（分片路径 fail closed，回 502 结果）', async () => {
    delete process.env.NODE_ENV
    delete process.env.CLA1_TEST_FETCH_INJECTION
    let calls = 0
    const spy = async () => { calls++; return new Response('x') }
    const result = await pipeUpstream('http://169.254.169.254/latest/meta-data/', { headers: {} }, stubRes(), undefined, {}, undefined, spy)
    assert.equal(result.ok, false)
    assert.equal(calls, 0)
  })
  await check('probeUpstream 边界：spy 钩子不被调用（HEAD 探测 fail closed）', async () => {
    delete process.env.NODE_ENV
    delete process.env.CLA1_TEST_FETCH_INJECTION
    let calls = 0
    const spy = async () => { calls++; return new Response('x') }
    const res = stubRes()
    const result = await probeUpstream('http://169.254.169.254/latest/meta-data/', { headers: {} }, res, undefined, {}, undefined, spy)
    assert.equal(calls, 0)
    assert.equal(res.statusCode, 200, '回退合成 HEAD（GET 路径仍 fail closed）')
  })
  await check('fetchNested 边界：经 markGuardedTransport 标记的钩子（每请求都走守卫分发）生产放行', async () => {
    delete process.env.NODE_ENV
    delete process.env.CLA1_TEST_FETCH_INJECTION
    const guarded = markGuardedTransport((url, options) => fetchUpstreamResponse(url, options))
    const nested = await fetchNested(`${BASE}/m3u`, {}, undefined, guarded)
    assert.ok(nested && nested.text.includes('守卫台'))
  })
  await check('fetchNested 边界：默认守卫直连本地安全 fixture 正常取回（回归）', async () => {
    const nested = await fetchNested(`${BASE}/m3u`)
    assert.ok(nested && nested.text.includes('守卫台'))
  })

  // ---- customSourceFetch：白名单直连可用；非白名单（本应走代理）fail closed ----
  await check('customSourceFetch：白名单目标固定直连；非白名单 fail closed（代理无法固定 DNS）', async () => {
    const ok = await customSourceFetch(`${BASE}/m3u`)
    assert.equal(ok.status, 200)
    await assert.rejects(customSourceFetch('http://cdn.example/live/x.m3u8'), /无法固定 DNS 连接/)
  })

  console.log(`\n全部通过（${passed} 项）`)
} finally {
  a.closeAllConnections?.(); b.closeAllConnections?.()
  a.close(); b.close()
  rmSync(DATA_DIR, { recursive: true, force: true })
}
process.exit(0)
