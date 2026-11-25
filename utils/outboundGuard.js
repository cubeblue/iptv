/**
 * 共享出站 URL 安全策略（CLA-1）：订阅拉取、HLS 清单/分片/密钥、自定义源代理入口共用。
 *
 * 目标：服务器代取外部内容时，不能被第三方内容（订阅列表 / 播放清单）指挥去访问
 * 内网、本机或云元数据服务（SSRF），也不能被 DNS 重绑定绕过检查。
 *
 * 手段：
 *   1. 静态校验（无 DNS）：只允许 http(s)、URL 不允许内嵌账号密码；
 *      字面 IP / 局域网主机名（localhost、.lan 等后缀）只有精确出现在白名单
 *      （system-config.json 的 safeLanAllow 或环境变量 msafeLanAllow，主机或主机:端口，
 *      不支持 CIDR / 通配）里才放行，否则拒绝并给出明确提示。
 *   2. 解析校验（直连出站时）：把域名**全部** A/AAAA 答案都查出来逐一校验，
 *      私网 / 链路本地 / 云元数据 / IPv4 映射 IPv6 / 保留段 / 文档段 / 组播一律拒绝；
 *      空答案、混合答案（一个公网一个私网）同样整体拒绝。
 *   3. 固定连接地址：校验过的答案通过自定义 lookup 直接用于连接，连接过程不再发起
 *      新的 DNS 查询（防「检查时公网、连接时 127.0.0.1」的重绑定）。同一 host:port 的
 *      连接在 60 秒内复用同一个固定地址池（keep-alive），减少 TLS 握手开销。
 *   4. 逐跳重校验：safeFetchDirect 自己跟随重定向时，每一跳都重新解析并校验；
 *      跨源跳转自动剥掉 Authorization / Cookie。
 *
 * 覆盖不到的诚实说明（详见 docs/SECURITY.md）：
 *   - 经「网络代理」（后台 proxy / HTTPS_PROXY）出站的请求，目标连接由代理建立、
 *     由代理解析 DNS，本机无法固定连接地址——这类路径只做静态校验；
 *   - 模块注入的 fetchImpl（含测试注入）由模块自己负责连接安全；
 *   - 抓取模块（Chromium 网页抓取）、EPG 源、台标下载、更新检查等出站不在本模块范围内。
 */

import http from 'node:http'
import https from 'node:https'
import dns from 'node:dns'
import { isIP } from 'node:net'
import { Readable } from 'node:stream'
import { safeLanAllow } from '../config.js'

/** 订阅正文上限：5000 个频道的 m3u 约 1.5 MB，16 MB 留足余量又挡住失控下载。 */
export const MAX_SUBSCRIPTION_BODY_BYTES = 16 * 1024 * 1024
/** 清单（HLS）正文上限：与 customSourceProxy.MAX_MANIFEST_BYTES 同量级，防「一条直播流当清单读」。 */
export const MAX_MANIFEST_BODY_BYTES = 4 * 1024 * 1024

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308])

/** 出站被策略拒绝的错误：调用方可按 .outboundDenied 识别并给用户可读提示。 */
export class OutboundDeniedError extends Error {
  constructor(message) {
    super(message)
    this.name = 'OutboundDeniedError'
    this.outboundDenied = true
  }
}

const deny = (message) => { throw new OutboundDeniedError(message) }

// ================= 地址分类 =================

function ipv6Words(host) {
  const halves = String(host || '').split('::')
  if (halves.length > 2) return null
  const parse = part => (part ? part.split(':') : []).map(word => (/^[0-9a-f]{1,4}$/.test(word) ? parseInt(word, 16) : NaN))
  const head = parse(halves[0])
  const tail = halves.length === 2 ? parse(halves[1]) : []
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0
  if (fill < 0) return null
  const words = [...head, ...new Array(fill).fill(0), ...tail]
  return words.length === 8 && words.every(Number.isInteger) ? words : null
}

const v4FromWords = (words) => [words[0] >> 8, words[0] & 255, words[1] >> 8, words[1] & 255]

/**
 * 非全球单播 IPv4 范围：私网、回环、链路本地（含云元数据 169.254.169.254）、
 * CGNAT、基准测试段（198.18/15，fake-ip 代理也用它——需要它的部署把目标域名精确加进白名单）、
 * 6to4 中继、组播与保留段。
 */
export function isPrivateIPv4Bytes(a, b, c) {
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192) {
    if (b === 0 || b === 168) return true
    if (b === 88 && c === 99) return true
  }
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return true
  if (a === 203 && b === 0 && c === 113) return true
  return a >= 224
}

export function isForbiddenIPv4(address) {
  const parts = String(address || '').split('.')
  if (parts.length !== 4 || parts.some(p => !/^\d{1,3}$/.test(p))) return true
  const [a, b, c] = parts.map(Number)
  if (a > 255 || b > 255 || c > 255 || Number(parts[3]) > 255) return true
  return isPrivateIPv4Bytes(a, b, c)
}

/**
 * 出站禁止的地址（任何一条解析答案命中即拒绝）：
 *  - IPv4：isPrivateIPv4Bytes 覆盖的私网/回环/元数据/保留段；
 *  - IPv6：未指定 / 回环 / IPv4 映射（::ffff:0:0/96 与 ::ffff:0:0:0/96，一律拒绝，
 *    不做「映射到公网 IPv4 就放行」——它本就不该出现在对外应答里）、NAT64 / 6to4 按
 *    嵌入的 IPv4 判、Teredo 整段拒绝、ULA / 链路本地 / 站点本地 / 组播 / 文档段。
 */
export function isForbiddenAddress(raw) {
  const address = String(raw || '').trim().toLowerCase().replace(/^\[|\]$/g, '')
  const family = isIP(address)
  if (family === 4) return isForbiddenIPv4(address)
  if (family === 6) {
    const w = ipv6Words(address)
    if (!w) return true
    const [a, b] = w
    if (w.every(x => x === 0)) return true                       // ::/128
    if (w.slice(0, 7).every(x => x === 0) && w[7] === 1) return true  // ::1/128
    if (w.slice(0, 5).every(x => x === 0) && w[5] === 0xffff) return true         // ::ffff:0:0/96
    if (w.slice(0, 4).every(x => x === 0) && w[4] === 0xffff && w[5] === 0) return true  // ::ffff:0:0:0/96
    if (a === 0x64 && b === 0xff9b && w.slice(2, 6).every(x => x === 0)) {
      return isPrivateIPv4Bytes(...v4FromWords(w.slice(6)))     // NAT64：看嵌入的 IPv4
    }
    if (a === 0x2002) return isPrivateIPv4Bytes(...v4FromWords(w.slice(1, 3)))      // 6to4：看嵌入的 IPv4
    if (a === 0x2001 && b === 0) return true                    // Teredo（嵌入地址被混淆）
    if ((a & 0xfe00) === 0xfc00) return true                    // ULA fc00::/7
    if ((a & 0xffc0) === 0xfe80) return true                    // 链路本地 fe80::/10
    if ((a & 0xffc0) === 0xfec0) return true                    // 站点本地 fec0::/10（已废弃）
    if ((a & 0xff00) === 0xff00) return true                    // 组播
    if (a === 0x2001 && b === 0xdb8) return true                // 文档段 2001:db8::/32
    return false
  }
  return true
}

/** 解析结果里的「全球单播」：是合法 IP 且不在禁止范围。 */
export function isGlobalAddress(raw) {
  const address = String(raw || '').trim().toLowerCase().replace(/^\[|\]$/g, '')
  const family = isIP(address)
  return family !== 0 && !isForbiddenAddress(address)
}

// ================= 白名单 =================

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$/

/**
 * 解析出站白名单文本（逗号 / 分号 / 空白分隔）。只认**精确**主机名或 IP（可选 :端口），
 * IPv6 用方括号（[::1]:8080）。CIDR、通配符、非法条目一律忽略并报告。
 * @returns {{ entries: Array<{host: string, port: string}>, rejected: string[] }}
 */
export function parseLanAllowlist(text) {
  const entries = []
  const rejected = []
  for (const raw of String(text || '').split(/[,;\s]+/).filter(Boolean)) {
    const item = raw.trim().toLowerCase()
    let host = ''
    let port = ''
    if (item.startsWith('[')) {
      const m = /^\[([0-9a-f:]+)\](?::(\d{1,5}))?$/.exec(item)
      if (m && isIP(m[1]) === 6) { host = m[1]; port = m[2] || '' }
      else { rejected.push(raw); continue }
    } else {
      const m = /^([^:]+)(?::(\d{1,5}))?$/.exec(item)
      if (!m) { rejected.push(raw); continue }
      host = m[1]
      port = m[2] || ''
      if (isIP(host) === 6) { rejected.push(raw); continue }   // 裸 IPv6 必须带方括号
      if (isIP(host) !== 4 && !HOSTNAME_RE.test(host)) { rejected.push(raw); continue }
    }
    if (port) {
      const p = Number(port)
      if (!Number.isInteger(p) || p < 1 || p > 65535) { rejected.push(raw); continue }
    }
    entries.push({ host, port })
  }
  return { entries, rejected }
}

let allowlistCache = { text: '\0', entries: [] }
/**
 * 生效的出站白名单（读取 config.js 的 live binding：system-config.json 的 safeLanAllow，
 * 或环境变量 msafeLanAllow）。非法条目只在文本变化时告警一次。
 */
export function defaultLanAllowlist() {
  // 同时读 config.js 的 live binding 与实时环境变量：ESM 静态 import 先于模块体执行，
  // config.js 可能早于 process.env 赋值加载；调用时再读环境变量可避免丢配置
  const text = String(safeLanAllow || process.env.msafeLanAllow || '').trim()
  if (text !== allowlistCache.text) {
    const { entries, rejected } = parseLanAllowlist(text)
    allowlistCache = { text, entries }
    if (rejected.length > 0) {
      console.warn(`[出站白名单] 忽略非法条目（只支持精确主机/IP，可带 :端口，不支持 CIDR/通配）: ${rejected.join(', ')}`)
    }
  }
  return allowlistCache.entries
}

function hostMatchesAllowlist(host, portText, allowlist) {
  return allowlist.some(entry => entry.host === host && (!entry.port || entry.port === portText))
}

/** URL 的主机（精确）是否在出站白名单里（供「白名单内直连、其余走代理」的出站选路用）。 */
export function isAllowlistedUrl(rawUrl, allowlist = defaultLanAllowlist()) {
  try {
    const url = new URL(String(rawUrl))
    return hostMatchesAllowlist(normalizeHost(url), url.port, allowlist)
  } catch {
    return false
  }
}

// ================= 校验 =================

function normalizeHost(url) {
  return url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '')
}

const ALLOWLIST_HINT = '如确需服务器访问该局域网/本机地址，请把它精确加入 system-config.json 的 safeLanAllow 或环境变量 msafeLanAllow（主机或主机:端口，不支持 CIDR/通配），详见 docs/SECURITY.md'

/**
 * 静态校验（不解析 DNS）：协议、内嵌凭据、字面 IP / 局域网主机名。
 * 所有出站路径（含经代理、模块注入 fetchImpl）都要先过这一关。
 * @returns {URL}
 */
export function assertStaticOutboundUrl(rawUrl, { allowlist = defaultLanAllowlist(), label = '出站请求' } = {}) {
  let url
  try { url = new URL(String(rawUrl)) } catch { deny(`${label}：不是有效的 URL`) }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') deny(`${label}：不支持的协议 ${url.protocol}`)
  if (url.username || url.password) deny(`${label}：URL 不允许内嵌账号密码（订阅地址的 user:pass 请用 Basic 认证头代替）`)
  const host = normalizeHost(url)
  const portText = url.port
  if (hostMatchesAllowlist(host, portText, allowlist)) return url
  if (isIP(host) === 4 || isIP(host) === 6) {
    if (isForbiddenAddress(host)) deny(`${label}：目标 ${host} 是私网/本机/保留地址，不在出站白名单内。${ALLOWLIST_HINT}`)
    return url
  }
  if (isLanHostname(host)) deny(`${label}：目标 ${host} 是局域网/本机主机名，不在出站白名单内。${ALLOWLIST_HINT}`)
  return url
}

/** 只在家里解析得到的域名后缀 / 单段主机名（与 customSourceProxy 的改写口径一致）。 */
export function isLanHostname(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '')
  if (!h) return true
  if (isIP(h)) return false
  if (!h.includes('.')) return true
  return /(?:^|\.)(?:localhost|local|lan|home|home\.arpa|internal|localdomain)$/.test(h)
}

const systemResolver = async (host) => {
  const answers = await dns.promises.lookup(host, { all: true, verbatim: true })
  return answers.map(a => ({ address: String(a.address).replace(/^\[|\]$/g, ''), family: a.family === 6 ? 6 : 4 }))
}

/**
 * 解析并校验出站目标：静态校验 + 全部 DNS 答案逐一校验（白名单精确命中则只固定、不判地址类别）。
 * 返回固定连接需要的 { host, portText, addresses, allowlisted, lan }；拒绝时抛 OutboundDeniedError。
 * @param {Function} [resolver] 测试注入的解析器：(host) => Promise<Array<{address, family}>>
 */
export async function resolveAndValidateTarget(rawUrl, {
  allowlist = defaultLanAllowlist(), resolver = systemResolver, label = '出站请求', hint = '',
} = {}) {
  const url = assertStaticOutboundUrl(rawUrl, { allowlist, label })
  const host = normalizeHost(url)
  const portText = url.port
  const allowlisted = hostMatchesAllowlist(host, portText, allowlist)
  const family = isIP(host)
  const addresses = family
    ? [{ address: host, family }]
    : await resolveHostAnswers(host, resolver, label, hint)
  if (!allowlisted) {
    const bad = addresses.find(a => !isGlobalAddress(a.address))
    if (bad) {
      deny(`${label}：${host} 的解析结果 ${bad.address} 不是全球单播地址（私网/本机/元数据/IPv4 映射 IPv6/混合解析答案一律拒绝），已拒绝出站。${hint || ALLOWLIST_HINT}`)
    }
  }
  // allowlisted = 管理员精确放行的目标（通常是局域网主机）：由调用方决定直连还是走代理
  return { host, portText, addresses, allowlisted }
}

async function resolveHostAnswers(host, resolver, label, hint) {
  let answers
  try {
    answers = await resolver(host)
  } catch (error) {
    deny(`${label}：${host} DNS 解析失败（${error?.message || error}），已拒绝出站。${hint || ''}`.trim())
  }
  if (!Array.isArray(answers) || answers.length === 0) {
    deny(`${label}：${host} 没有可用的解析答案，已拒绝出站（空答案视同不安全）。${hint || ''}`.trim())
  }
  const out = []
  for (const item of answers) {
    const address = String(item?.address || '').replace(/^\[|\]$/g, '').toLowerCase()
    const family = isIP(address)
    if (family !== 4 && family !== 6) continue
    out.push({ address, family })
  }
  if (out.length === 0) deny(`${label}：${host} 没有可用的解析答案，已拒绝出站。${hint || ''}`.trim())
  return out
}

// ================= 固定地址的连接 =================

const PIN_TTL_MS = 60 * 1000
const pinPool = new Map()   // host:port -> { addressesKey, agent }
const retiredAgents = []    // 被替换/淘汰的 agent：空闲后销毁，绝不动在途连接

/** 空闲连接池退役：没有在用 socket 的旧 agent 直接销毁（在途请求用过的 agent 留到下一轮）。 */
function sweepRetiredAgents() {
  for (let i = retiredAgents.length - 1; i >= 0; i--) {
    const agent = retiredAgents[i]
    if (Object.keys(agent.sockets).length === 0) {
      agent.destroy()
      retiredAgents.splice(i, 1)
    }
  }
  if (retiredAgents.length > 256) retiredAgents.splice(0, retiredAgents.length - 256)
}

/**
 * 同一 host:port 且解析答案没变时复用连接池；答案变了换新池（旧池退役、空闲后销毁），
 * 保持「校验过什么就连什么」。池按插入序淘汰（上限 200），淘汰的 agent 同样走退役。
 */
function pinnedAgentFor(protocol, host, portText, addresses) {
  sweepRetiredAgents()
  const key = `${protocol}|${host}|${portText}`
  const addressesKey = addresses.map(a => `${a.family}:${a.address}`).join('|')
  const entry = pinPool.get(key)
  if (entry && entry.addressesKey === addressesKey) return entry.agent
  const agent = new (protocol === 'https:' ? https : http).Agent({ keepAlive: true, maxSockets: 6 })
  if (entry) retiredAgents.push(entry.agent)
  pinPool.delete(key)
  pinPool.set(key, { addressesKey, agent })
  while (pinPool.size > 200) {
    const oldest = pinPool.keys().next()
    if (oldest.done) break
    retiredAgents.push(pinPool.get(oldest.value).agent)
    pinPool.delete(oldest.value)
  }
  return agent
}

/** 请求会带 abort 的 Signal；body 支持 string / Buffer / Uint8Array。 */
function requestWithPin(target, pinned, { method, headers = {}, body, signal, timeoutMs, family }) {
  return new Promise((resolve, reject) => {
    const isTls = target.protocol === 'https:'
    const port = target.port ? Number(target.port) : (isTls ? 443 : 80)
    const preferred = family === 4 || family === 6 ? family : (pinned.addresses.some(a => a.family === 4) ? 4 : 6)
    const chosen = pinned.addresses.find(a => a.family === preferred) || pinned.addresses[0]
    if (!chosen) { reject(new OutboundDeniedError(`出站请求：${target.host} 没有可用连接地址`)); return }
    // 固定 lookup：只从已校验的答案里选地址，绝不发起新的 DNS 查询。
    // 兼容 Node 20+ 的调用形态：opts 可能是 { family, hints, all }，all=true 时要回数组
    // （autoSelectFamily 会这样调），回调可能是第二或第三个参数。
    const lookup = (hostname, opts, cb) => {
      if (typeof opts === 'function') { cb = opts; opts = {} }
      const wantFamily = opts?.family === 4 || opts?.family === 6 ? opts.family : preferred
      const selected = pinned.addresses.find(a => a.family === wantFamily) || chosen
      if (opts?.all) return cb(null, [{ address: selected.address, family: selected.family }])
      cb(null, selected.address, selected.family)
    }
    const mod = isTls ? https : http
    let resRef = null
    const req = mod.request({
      hostname: pinned.host,
      port,
      path: target.pathname + target.search,   // 路径与查询串必须原样带上（漏了会请求到根路径）
      method,
      headers: { ...headers, host: target.host },   // Host 头保持原始主机（含端口/IPv6 方括号）
      lookup,
      agent: pinnedAgentFor(target.protocol, pinned.host, pinned.portText, pinned.addresses),
      servername: isTls ? pinned.host : undefined,
    }, res => { resRef = res; resolve({ res, finalUrl: target.href }) })
    req.once('error', reject)
    const abortError = () => Object.assign(new Error('请求已中止'), { name: 'AbortError' })
    const onAbort = () => {
      // 响应头已到：销毁响应流让 body 读取方拿到 AbortError（销毁请求侧只会冒出 ECONNRESET）
      if (resRef) resRef.destroy(abortError())
      else req.destroy(abortError())
    }
    if (signal) {
      if (signal.aborted) { onAbort(); return }
      signal.addEventListener('abort', onAbort, { once: true })
    }
    let timer = null
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      timer = setTimeout(() => {
        const err = Object.assign(new Error(`请求超时 ${timeoutMs}ms`), { name: 'AbortError' })
        if (resRef) resRef.destroy(err)
        else req.destroy(err)
      }, timeoutMs)
    }
    req.once('close', () => {
      if (signal) signal.removeEventListener('abort', onAbort)
      if (timer) clearTimeout(timer)
    })
    if (body === undefined || body === null) req.end()
    else if (Buffer.isBuffer(body) || typeof body === 'string' || body instanceof Uint8Array) req.end(body)
    else req.end(String(body))
  })
}

async function collectWebBody(webBody) {
  const chunks = []
  let size = 0
  for await (const chunk of webBody || []) {
    const buf = Buffer.from(chunk)
    size += buf.length
    chunks.push(buf)
  }
  return Buffer.concat(chunks, size)
}

/** 把 node http 响应包装成 fetch 风格（status / ok / headers.get / url / body / text / arrayBuffer / cancel）。 */
function makeResponse(res, finalUrl, method) {
  const webBody = method === 'HEAD' || res.statusCode === 204 || res.statusCode === 304 ? null : Readable.toWeb(res)
  // 必须是真实 Headers 实例：调用方会把它当 Headers 重建/复制（如 sztv 的
  // `new Headers(response.headers)`），纯 {get,has} 对象在那一步会丢光全部响应头
  // （content-range 等），下游断言与播放器行为都会受影响。
  const headers = new Headers()
  for (const [name, value] of Object.entries(res.headers)) {
    if (value != null) headers.set(String(name), String(value))
  }
  return {
    status: res.statusCode || 0,
    ok: res.statusCode >= 200 && res.statusCode < 300,
    url: finalUrl,
    headers,
    body: webBody,
    text: async () => (webBody ? (await collectWebBody(webBody)).toString('utf8') : ''),
    arrayBuffer: async () => {
      if (!webBody) return new ArrayBuffer(0)
      const buf = await collectWebBody(webBody)
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
    },
    cancel: async () => { res.destroy() },
  }
}

const CREDENTIAL_HEADERS = new Set(['authorization', 'cookie', 'proxy-authorization'])

/**
 * 直连安全 fetch（core http/https）：每一跳都解析全部答案并校验、用固定地址连接；
 * 跟随重定向时逐跳重校验，跨源跳转剥掉凭据头。
 * @param {string} rawUrl
 * @param {object} [options] method/headers/body/signal/redirect('follow'|'manual')/maxRedirects/timeoutMs/
 *   family(4|6)/allowlist/resolver/pinned(跳过首跳解析)/label
 */
export async function safeFetchDirect(rawUrl, options = {}) {
  const {
    method = 'GET', headers = {}, body, signal, redirect = 'follow', maxRedirects = 3,
    timeoutMs = 30000, family, allowlist = defaultLanAllowlist(), resolver = systemResolver,
    pinned, label = '出站请求',
  } = options
  let current = String(rawUrl)
  let currentHeaders = headers
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const target = new URL(current)
    const pin = (pinned && hop === 0) ? pinned : await resolveAndValidateTarget(current, { allowlist, resolver, label })
    const { res, finalUrl } = await requestWithPin(target, pin, { method, headers: currentHeaders, body, signal, timeoutMs, family })
    const status = res.statusCode || 0
    if (redirect === 'manual' || !REDIRECT_STATUS.has(status)) return makeResponse(res, finalUrl, method)
    const location = res.headers.location
    res.resume(); res.destroy()   // 丢弃重定向响应体
    if (!location) deny(`${label}：上游重定向缺少地址`)
    if (hop === maxRedirects) deny(`${label}：上游重定向次数过多（> ${maxRedirects}）`)
    const next = new URL(location, current)
    if (next.origin !== target.origin) {
      // 大小写无关地剥掉凭据头（Authorization / Cookie / Proxy-Authorization 的任意大小写写法）
      currentHeaders = { ...currentHeaders }
      for (const name of Object.keys(currentHeaders)) {
        if (CREDENTIAL_HEADERS.has(name.toLowerCase())) delete currentHeaders[name]
      }
    }
    current = next.href
  }
  deny(`${label}：上游重定向次数过多`)
}

/** 订阅拉取用的直连安全 fetch（默认白名单 + 系统解析器），作为 fetchAndParseM3u 的默认 fetchImpl。 */
export function createSubscriptionSafeFetch() {
  return (url, options = {}) => safeFetchDirect(url, { ...options, label: '订阅拉取' })
}

// ================= 有上限的响应体读取 =================

async function discardBody(response) {
  try {
    if (typeof response?.body?.cancel === 'function') await response.body.cancel()
    else if (typeof response?.body?.destroy === 'function') response.body.destroy()
  } catch { /* 已断开就算了 */ }
}

export function bodyTooLargeError(label, maxBytes) {
  return new Error(`${label}响应体超过上限 ${Math.round(maxBytes / 1024 / 1024)} MB，已中止读取`)
}

/**
 * 按字节数有上限地读取响应体（先查 Content-Length 再按流计数，防 chunked 无长度声明的大响应）。
 * 超限时中止并销毁上游响应，抛出错误。兼容 node-fetch / undici / safeFetchDirect 的响应体。
 */
export async function readCappedBody(response, maxBytes, label = '出站') {
  const declared = Number(response?.headers?.get?.('content-length'))
  if (Number.isFinite(declared) && declared > maxBytes) {
    await discardBody(response)
    throw bodyTooLargeError(label, maxBytes)
  }
  const chunks = []
  let size = 0
  for await (const chunk of response?.body || []) {
    const buf = Buffer.from(chunk)
    size += buf.length
    if (size > maxBytes) {
      await discardBody(response)
      throw bodyTooLargeError(label, maxBytes)
    }
    chunks.push(buf)
  }
  return Buffer.concat(chunks, size)
}
