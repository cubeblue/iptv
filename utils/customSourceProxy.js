/**
 * 自定义源播放入口：「经网络代理转发」（useProxy）与最高画质起播（topFirst）。
 * topFirst 每次播放现取主清单，把最高档排在首位；未启用网络代理时只转发清单，媒体仍由播放器直连。
 *
 * 内置模块走不走代理是声明制（registry.js 的 outbound: 'proxy'，固定四处），用户在这里改不了；
 * 内置的「精选频道」订阅也没有这个开关。这里只管用户自己加的源：用户知道自己的哪份列表在大陆连不上，
 * 交给用户自己勾，比我们替第三方列表判断准。
 *
 * 勾上之后：
 *   1. 拉订阅列表经网络代理（externalSources.updateSubscriptionSource）；
 *   2. 源里的 http(s) 频道在订阅里改写成本机固定入口 ${replace}/proxy/cp-<hex>.m3u8，
 *      播放时：有生效代理 → 服务器经代理取清单，清单和分片都由服务器转发（与海外频道同一条全代理链路）；
 *              没有生效代理 → 302 回原地址，由播放器直连（和没勾时一样）；
 *              取回来不是 HLS（FLV、TS 裸流等）→ 302 回原地址，由播放器直连。
 *   局域网地址（udpxy 之类）、rtmp/rtp/udp 等非 HTTP 地址、.flv 地址不改写，照旧原样输出。
 *
 * 订阅里写的是固定入口而不是按代理状态二选一，是为了让后台改代理设置后不用重新生成订阅、
 * 播放器也不用刷新就跟着变（海外频道同理）。频道的身份（隐藏、改名、归类、排序）仍按原地址算，
 * 写盘时带 identity-url，开关一开一关这些设置都不丢。
 *
 * 引用 cp-<hex> 按「源 id + 频道名 + 剥掉时效参数的原地址」算：订阅刷新换了签名，播放器收藏的地址不变，
 * 播放时总是取最新的原地址。
 *
 * 后台网页播放（web 模式）：自定义源的频道地址在别人的服务器上，多数不给网页跨域许可，浏览器读不到清单；
 * 地址没有 .m3u8 后缀的，浏览器还认不出是直播。后台页面和独立播放页播这类频道时，拿原地址来问
 * /proxy/web.m3u8?u=<原地址>：地址在用户自己的源里（webRefFor 查得到）且是 HLS，就由服务器取清单、转发分片；
 * 没勾「经网络代理转发」的源服务器直连去取，勾了且代理生效的照旧经代理。不在源里、不是 HLS、服务器取不到，
 * 都回出错状态，页面退回浏览器直连（和以前一样）。只影响网页播放，订阅里的地址不变。
 * 只认源里已有的地址、且同样只认公网 http(s)：订阅内容是第三方给的，不能让它指挥服务器去取任意地址或家里的机器。
 */
import { createHash } from 'node:crypto'
import { isIP } from 'node:net'

import { sanitizeOpts } from './channelOpts.js'
import { testFetchInjectionEnabled } from './testEnv.js'
import { printYellow } from './colorOut.js'
import { fetchUpstreamResponse, markGuardedTransport } from './hlsProxy.js'
import { topVariantFirst } from './hlsTopFirst.js'
import { isPrivateAddress } from './logoCache.js'
import { describeProxyFailure, outboundProxyUrl } from './outboundProxy.js'
import { assertStaticOutboundUrl, defaultLanAllowlist, isAllowlistedUrl, resolveAndValidateTarget, safeFetchDirect } from './outboundGuard.js'
import { stripVolatileParams } from './urlIdentity.js'

export const REF_PREFIX = 'cp-'
const REF_RE = /^cp-[0-9a-f]{16}$/
// 清单是播放器起播（和每次轮询）时现取的，取不到要尽快告诉播放器，别让它干等
const MANIFEST_TIMEOUT_MS = 8000
// 与 appUtils.inlineResolvedManifest 的上限一致：超过它的不当清单处理
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024
// 同一原因的日志多久打一次：播放器失败后是 100ms 级的连环重试，逐次打印会淹没日志
const LOG_EVERY_MS = 30 * 1000

export function claimsRef(ref) {
  return REF_RE.test(String(ref || ''))
}

/** 这个频道的本机固定引用（单个路径段，写成 ${replace}/proxy/<ref>.m3u8）。 */
export function proxyRefFor(sourceId, name, url) {
  const digest = createHash('sha1')
    .update(`${sourceId}\n${name || ''}\n${stripVolatileParams(String(url || ''))}`)
    .digest('hex')
  return REF_PREFIX + digest.slice(0, 16)
}

/**
 * 局域网 / 本机主机名：字面 IP 按私网段判（198.18.0.0/15 的 fake-ip 不算，那是代理软件给域名的假地址），
 * 域名按 localhost、.local、.lan 这类只在家里解析得到的后缀，和不带点的单段主机名判。
 */
export function isLanHost(hostname) {
  const host = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '')
  if (!host) return true
  if (isIP(host)) return isPrivateAddress(host)
  if (!host.includes('.')) return true
  return /(?:^|\.)(?:localhost|local|lan|home|home\.arpa|internal|localdomain)$/.test(host)
}

function isLanUrl(raw) {
  try { return isLanHost(new URL(String(raw)).hostname) } catch { return false }
}

/**
 * 开了开关的源里的频道地址改写（proxiableUrl）沿用 isLanHost 的宽松口径（198.18/15 fake-ip
 * 不算局域网）；真正出站时的强制校验在 customSourceFetch / hlsProxy 的共享策略里，两套口径
 * 各管一段，见 docs/SECURITY.md。
 */

/** 开了开关的源里，哪些频道改由服务器转发：公网上的 http(s) 地址，FLV 除外（转发链路只管 HLS）。 */
export function proxiableUrl(raw) {
  let url
  try { url = new URL(String(raw || '')) } catch { return false }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  if (isLanHost(url.hostname)) return false
  return !/\.flv$/i.test(url.pathname)
}

/**
 * 开了开关的源的出站请求（CLA-1 起先过共享出站策略，见 utils/outboundGuard.js）：
 *  - 目标在白名单（safeLanAllow / msafeLanAllow 的精确主机/IP）里：本机直连，连接地址固定为
 *    校验过的解析答案（代理够不着家里的机器）；
 *  - 其余地址：静态校验（协议 / 内嵌凭据 / 字面 IP / 局域网主机名须在白名单）后经网络代理
 *    （后台填的优先，没填沿用 HTTPS_PROXY / 系统代理，见 outboundProxy.outboundFetch）。
 *    经代理出站的连接由代理解析建立、DNS 由代理解析，本机无法固定地址——见 docs/SECURITY.md 的诚实说明。
 */
export async function customSourceFetch(url, options = {}) {
  const allowlist = defaultLanAllowlist()
  // CLA-1：出站传输只有两种：
  //  - 精确白名单（safeLanAllow / msafeLanAllow）里的目标：本机直连，连接地址固定为校验过的答案；
  //  - 其余目标本应经网络代理——但代理出站时连接与 DNS 由代理解析，本机无法固定地址，
  //    无法满足「校验过什么就连什么」→ **fail closed**，不静默走代理、也不静默绕过代理改直连。
  // 静态校验仍先跑一遍，字面私网 IP / 局域网主机名只有白名单能放行。
  assertStaticOutboundUrl(url, { allowlist, label: '自定义源' })
  if (isAllowlistedUrl(url, allowlist)) {
    const pinned = await resolveAndValidateTarget(url, { allowlist, label: '自定义源(白名单直连)' })
    return safeFetchDirect(url, { ...options, pinned, label: '自定义源(白名单直连)' })
  }
  throw new Error('「经网络代理转发」出站无法固定 DNS 连接（CLA-1 安全默认），已停用。请取消该源的「经网络代理转发」、或把目标精确加入 safeLanAllow/msafeLanAllow 白名单改由服务器直连；详见 docs/SECURITY.md')
}

// 代理已接通、往对方那一步失败时，报错后面跟的一句：用户最常见的是把自己网络本来就能播的源（运营商 IPTV 等）也勾上了
const TARGET_FAILURE_HINT = '。从代理出去连不上这个地址：用自己网络能直接播的源不用勾「经网络代理转发」；代理软件用规则模式的，看看这个地址走了哪条线路'

const OPT_HEADERS = { 'http-user-agent': 'User-Agent', 'http-referrer': 'Referer', 'http-origin': 'Origin' }

/**
 * 频道的 #EXTVLCOPT 请求头（含「播放时也带上这个 UA」补上的那条）→ 服务器回源时发的请求头。
 * 播放器原本会自己带上这些头，改成服务器取流后得由服务器替它带。
 * 返回函数形态：hlsProxy 只有函数形态的 User-Agent 会原样发出（固定对象一律换成统一 UA）。
 */
export function upstreamHeadersOf(opts) {
  const headers = {}
  for (const opt of sanitizeOpts(opts)) {
    const eq = opt.indexOf('=')
    const name = OPT_HEADERS[opt.slice(0, eq)]
    if (name) headers[name] = opt.slice(eq + 1)
  }
  return Object.keys(headers).length ? () => ({ ...headers }) : undefined
}

/** 回看等播放参数接回原地址（播放器把它们拼在本机入口后面）。 */
function withQuery(url, query) {
  const text = new URLSearchParams(query && typeof query === 'object' ? query : {}).toString()
  if (!text) return url
  const hashAt = url.indexOf('#')
  const head = hashAt === -1 ? url : url.slice(0, hashAt)
  const tail = hashAt === -1 ? '' : url.slice(hashAt)
  return `${head}${head.includes('?') ? '&' : '?'}${text}${tail}`
}

function hostOf(url) {
  try { return new URL(url).host } catch { return '' }
}

/** 按原地址查频道用的键：原样一份，规范化后（主机名小写、补上根路径）再一份，网页传来哪种写法都对得上。 */
function urlKeys(raw) {
  const text = String(raw || '').trim()
  if (!text) return []
  try {
    const href = new URL(text).href
    return href === text ? [text] : [text, href]
  } catch {
    return [text]
  }
}

/**
 * 本机入口 ${replace}/proxy/cp-….m3u8 不带「?」：原地址带 ? 的源常把回看模板写成 &playseek=…，
 * 播放器直接拼在入口后面会拼成 cp-….m3u8&playseek=…，认不出来就 404。写盘时把开头的 & 换成 ?，
 * 参数到了 resolve 再按原地址接回（withQuery 会按原地址重新选 ? 还是 &）。
 */
export function catchupForProxyEntry(channel) {
  const source = channel?.catchupSource
  if (typeof source !== 'string' || !source.startsWith('&')) return channel
  return { ...channel, catchupSource: `?${source.slice(1)}` }
}

/**
 * 读清单正文；开头不是 #EXTM3U（FLV、TS 裸流、网页）就停下返回 null，不把一条直播流读进内存。
 */
async function readHlsText(response) {
  const chunks = []
  let size = 0
  let checked = false
  for await (const chunk of response.body || []) {
    const buf = Buffer.from(chunk)
    chunks.push(buf)
    size += buf.length
    if (!checked) {
      const head = Buffer.concat(chunks, size).toString('utf8').trimStart()
      if (head.length >= 7) {
        if (!head.startsWith('#EXTM3U')) return null
        checked = true
      }
    }
    if (size > MAX_MANIFEST_BYTES) return null
  }
  const text = Buffer.concat(chunks, size).toString('utf8')
  return text.trimStart().startsWith('#EXTM3U') ? text : null
}

/**
 * 播放请求的解析者。不是抓取模块（不进注册表、后台没有卡片），由 app.js 用 registerRefResolver 挂上，
 * resolverFor 在模块都不认领时才问它。
 *
 * @param {object} deps
 * @param {() => Array<{ref, name, url, useProxy?, topFirst?, opts?, sourceId?, sourceName?}>} deps.getChannels 改写了播放入口的频道
 * @param {() => Array<{ref, name, url, useProxy?, topFirst?, opts?, sourceId?, sourceName?}>} deps.getWebChannels 后台网页播放时可由服务器转发的频道（含没改写入口的）
 * @param {() => unknown} deps.getVersion 源配置的版本号；变了才重建索引（订阅刷新会换掉原地址里的签名）
 */
export function createCustomProxyResolver({
  getChannels,
  getWebChannels = () => [],
  getVersion = () => undefined,
  // CLA-1：经网络代理出站已按安全默认停用（无法固定 DNS 连接），仅显式测试注入
  // （NODE_ENV=test 且 CLA1_TEST_FETCH_INJECTION=1，见 utils/testEnv.js）下才经 fetchImpl 放行；
  // 直连（web / 最高画质起播）交给 hlsProxy 的守卫直连（全量 DNS 校验 + 固定连接地址）。
  // 测试注入的替身由注入方自己负责连接安全
  fetchImpl,
  directFetchImpl,
  proxyEnabled = () => Boolean(outboundProxyUrl()),
  log = printYellow,
  now = Date.now,
} = {}) {
  let index = null
  // 网页播放单独一份索引：播放器拿着旧入口来问没改写过的频道，仍要回「已关闭播放处理」，不能被这份名单接住
  let webIndex = null
  let webByUrl = null
  let indexVersion
  const lastLogged = new Map()

  function note(key, message) {
    const at = now()
    if (at - (lastLogged.get(key) || 0) < LOG_EVERY_MS) return
    if (lastLogged.size > 2000) lastLogged.clear()
    lastLogged.set(key, at)
    log(message)
  }

  function refresh() {
    const version = getVersion()
    if (index && version === indexVersion) return
    index = new Map()
    for (const channel of getChannels() || []) {
      if (channel && claimsRef(channel.ref) && channel.url) index.set(channel.ref, channel)
    }
    webIndex = new Map()
    webByUrl = new Map()
    for (const channel of getWebChannels() || []) {
      if (!channel || !claimsRef(channel.ref) || !channel.url) continue
      if (!webIndex.has(channel.ref)) webIndex.set(channel.ref, channel)
      // 两个源列了同一个地址：取先出现的那个，取的是同一路流
      for (const key of urlKeys(channel.url)) if (!webByUrl.has(key)) webByUrl.set(key, channel.ref)
    }
    indexVersion = version
  }

  function lookup(ref) {
    refresh()
    return index.get(ref)
  }

  function lookupWeb(ref) {
    refresh()
    return webIndex.get(ref)
  }

  /** 后台网页播放：按频道原地址查它的引用；不在用户自己的源里就没有（返回空串）。 */
  function webRefFor(rawUrl) {
    refresh()
    for (const key of urlKeys(rawUrl)) {
      const ref = webByUrl.get(key)
      if (ref) return ref
    }
    return ''
  }

  async function resolve(ref, ctx = {}) {
    // web：后台网页播放（app.js 的 /proxy/web.m3u8 入口才会带）。清单和分片一律由服务器转发，浏览器不直连对方
    const web = ctx.web === true
    const entry = claimsRef(ref) ? (web ? lookupWeb(String(ref)) : lookup(String(ref))) : null
    if (!entry) {
      return web
        ? { url: '', status: 404, silent: true, desc: '这个地址不在已启用的自定义源里' }
        : { url: '', status: 404, desc: '这个自定义源频道已更新，或已关闭播放处理，请在播放器里刷新订阅' }
    }
    // 直连 / 抓取源只有一个频道，源名就是台名，不重复写两遍
    const label = `${entry.sourceName && entry.sourceName !== entry.name ? entry.sourceName : '自定义源'}「${entry.name}」`
    const url = withQuery(entry.url, ctx.query)
    const proxied = entry.useProxy === true && proxyEnabled()
    const topFirst = entry.topFirst === true
    if (!web && !proxied && !topFirst) {
      note(`direct|${entry.sourceId || ''}`, `${entry.sourceName || '自定义源'}：没有生效的网络代理，开了「经网络代理转发」的频道暂由播放器直连`)
      // directRedirect：app.js 据此直接 302，不因入口在 /proxy/ 下就改由服务器取清单、转发分片
      return { url, directRedirect: 'no-proxy', desc: `${label} 没有生效的网络代理，改由播放器直连` }
    }
    if (proxied && !testFetchInjectionEnabled()) {
      // CLA-1：经网络代理出站无法固定 DNS 连接 → fail closed（不静默绕过用户的代理设置改直连）。
      // 错误里给出两条出路：取消开关改直连，或把目标精确加入白名单（白名单走校验+固定直连）。
      // 仅在显式测试注入（NODE_ENV=test 且 CLA1_TEST_FETCH_INJECTION=1）下放行代理传输，供离线测试用。
      return {
        url: '', status: 502, silent: true,
        desc: `${label}「经网络代理转发」出站无法固定 DNS 连接（CLA-1 安全默认），已停用。请取消该源的「经网络代理转发」改由服务器直连，或把目标精确加入 safeLanAllow/msafeLanAllow 白名单；详见 docs/SECURITY.md`,
      }
    }
    const upstreamHeaders = upstreamHeadersOf(entry.opts)
    try {
      // 直连（web 网页播放 / 最高画质起播）：交给 hlsProxy 的守卫直连（全量 DNS 校验 + 固定地址）；
      // 测试注入的替身由注入方自己负责连接安全
      const response = await fetchUpstreamResponse(url, {
        signal: AbortSignal.timeout(MANIFEST_TIMEOUT_MS),
        upstreamHeaders,
        headers: { Accept: 'application/vnd.apple.mpegurl, */*' },
        fetchImpl: proxied ? fetchImpl : directFetchImpl,
      })
      if (!response.ok) {
        await response.body?.cancel?.().catch(() => {})
        throw new Error(`对方回 HTTP ${response.status}`)
      }
      const text = await readHlsText(response)
      if (text == null && web) {
        // 网页播放不能 302 回原地址（跨域跳转浏览器读不到）：明说不是 HLS，页面自己退回浏览器直连。
        // MP4 之类本来就该浏览器直接播，不算异常，不打日志
        return { url: '', status: 404, silent: true, desc: `${label} 不是 HLS 直播，网页里由浏览器直接播放` }
      }
      if (text == null) {
        // 转发链路只管 HLS；FLV、TS 裸流这类交还给播放器，和没开开关时一样
        note(`nonhls|${entry.ref}`, `${label} 不是 HLS 直播，改由播放器直连（自定义源播放处理只支持 HLS）`)
        return { url, directRedirect: 'not-hls', desc: `${label} 不是 HLS 直播，改由播放器直连` }
      }
      const manifestUrl = response.url || url
      return {
        url: manifestUrl,
        ...(proxied || web ? { proxyHls: true } : { relayHls: true }),
        manifestText: topFirst ? topVariantFirst(text) : text,
        manifestUrl,
        upstreamHeaders,
        desc: `${label}${topFirst ? ' 最高画质优先' : ''}${proxied ? ' 经网络代理转发' : ''}${web ? ' 网页播放由服务器转发' : ''}`,
      }
    } catch (error) {
      // 和「测试」按钮同一套话：分得清是连代理就失败，还是代理接通后对方那一步失败
      const { stage, message } = proxied
        ? error?.proxyFailure || describeProxyFailure(error)
        : { stage: '', message: error?.message || String(error) }
      const reason = `${message}${stage === 'target' ? TARGET_FAILURE_HINT : ''}`
      // 开了代理就不悄悄绕过它直连：用户勾这个开关，多半正是因为直连不通
      const action = proxied ? '经网络代理取清单' : topFirst ? '取最高画质清单' : '取清单'
      note(`fail|${entry.ref}`, `${label} ${action}失败（${hostOf(url)}）：${reason}`)
      return { url: '', status: 502, silent: true, desc: `${label} ${action}失败：${reason}` }
    }
  }

  return {
    id: 'custom-source-proxy',
    name: '自定义源播放处理',
    // 回看参数由 resolve 自己接回原地址（原地址不一定带 ?，外壳的 & 拼接会拼坏）
    capabilities: { resolve: true, catchup: false },
    relayProxyCompatible: true,
    claimsRef,
    resolve,
    webRefFor,
    // /proxy 或浏览器全转发模式的分片回源。CLA-1：经网络代理出站无法固定 DNS 连接 → fail closed；
    // 直连走 hlsProxy 守卫直连（全量校验 + 固定地址）。
    // 本钩子**每个请求**都经 fetchUpstreamResponse 守卫分发（生产：无注入 → 校验+固定直连；
    // 测试注入的 fetchImpl/directFetchImpl 由 fetchUpstreamResponse 内的测试门把关），
    // 因此打上受信传输标记，允许通过 hlsProxy 公共分发边界（assertGuardedTransport）。
    fetchProxyMedia: markGuardedTransport((ref, _config, url, options) => {
      const entry = lookup(ref) || lookupWeb(ref)
      if (!entry) throw new Error('自定义源频道已更新，请刷新订阅')
      if (entry.useProxy === true && proxyEnabled() && !testFetchInjectionEnabled()) {
        throw new Error('「经网络代理转发」出站无法固定 DNS 连接（CLA-1 安全默认），已停用。详见 docs/SECURITY.md')
      }
      return fetchUpstreamResponse(url, {
        ...options,
        fetchImpl: entry.useProxy === true && proxyEnabled() ? fetchImpl : directFetchImpl,
      })
    }),
  }
}
