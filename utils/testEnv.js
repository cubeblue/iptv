// CLA-1：出站 fetch 注入（测试替身）的放行判定。
//
// 受保护出站路径（订阅拉取 / HLS 上游 / 自定义源代理传输）生产环境只允许内置守卫直连；
// 测试替身 fetchImpl 仅在「NODE_ENV=test 且 CLA1_TEST_FETCH_INJECTION=1 同时成立」时放行。
// 单设 CLA1_TEST_FETCH_INJECTION=1（NODE_ENV 不是 test）不放行——运行时不存在任何
// 面向用户的「绕过出站安全校验」开关，环境变量误设（如忘记删）不会削弱生产路径。
export function testFetchInjectionEnabled() {
  return process.env.NODE_ENV === 'test' && process.env.CLA1_TEST_FETCH_INJECTION === '1'
}
