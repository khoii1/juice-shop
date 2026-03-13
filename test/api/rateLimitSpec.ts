/*
 * Rate Limiting & Anti-Bruteforce Tests
 * Kiểm thử: Phân vùng tương đương (EP) + Giá trị biên (BVA)
 * Endpoints: /rest/user/login | /rest/user/reset-password | /rest/2fa/verify
 */

import * as frisby from 'frisby'

jest.setTimeout(60000)

const REST_URL = 'http://localhost:3000/rest'
const jsonHeader = {
  'content-type': 'application/json',
  'X-Rate-Limit-Test': 'true'
}

// Helper: wrap frisby thành Promise chuẩn để dùng với async/await
async function send (
  url: string,
  headers: Record<string, string>,
  body: Record<string, unknown>
): Promise<void> {
  await new Promise<void>((resolve) => {
    frisby.post(url, { headers, body }).then(
      () => {
        resolve()
      },
      () => {
        resolve()
      }
    )
  })
}

// Helper: wrap frisby + kiểm tra status code, reject nếu sai
async function sendExpect (
  url: string,
  headers: Record<string, string>,
  body: Record<string, unknown>,
  expectedStatus: number,
  checkJsonTypes?: Record<string, unknown>
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let spec = frisby
      .post(url, { headers, body })
      .expect('status', expectedStatus)
    if (checkJsonTypes != null) {
      spec = spec.expect('jsonTypes', checkJsonTypes)
    }
    spec.then(
      () => {
        resolve()
      },
      (err: unknown) => {
        reject(err)
      }
    )
  })
}

// Mỗi nhóm test dùng IP ảo riêng để không ảnh hưởng lẫn nhau
const IP = {
  LOGIN_EP_VALID: '203.0.113.1',
  LOGIN_EP_INVALID: '203.0.113.2',
  LOGIN_EP_BLOCKED: '203.0.113.3',
  LOGIN_BVA_1: '203.0.113.10',
  LOGIN_BVA_9: '203.0.113.19',
  LOGIN_BVA_10: '203.0.113.20',
  LOGIN_BVA_11: '203.0.113.21',
  RESET_EP_INVALID: '203.0.113.31',
  RESET_EP_BLOCKED: '203.0.113.32',
  RESET_BVA_1: '203.0.113.40',
  RESET_BVA_4: '203.0.113.44',
  RESET_BVA_5: '203.0.113.45',
  RESET_BVA_6: '203.0.113.46',
  OTP_EP_INVALID: '203.0.113.61',
  OTP_EP_BLOCKED: '203.0.113.62',
  OTP_BVA_1: '203.0.113.70',
  OTP_BVA_9: '203.0.113.79',
  OTP_BVA_10: '203.0.113.80',
  OTP_BVA_11: '203.0.113.81'
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. LOGIN  (max: 10 lần / 15 phút)
// ─────────────────────────────────────────────────────────────────────────────
describe('[Login] Phân vùng tương đương (max = 10 / 15 phút)', () => {
  it('EP1 - Vùng hợp lệ: Thông tin đúng → HTTP 200', () => {
    return frisby
      .post(REST_URL + '/user/login', {
        headers: { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_EP_VALID },
        body: { email: 'admin@juice-sh.op', password: 'admin123' }
      })
      .expect('status', 200)
  })

  it('EP2 - Vùng không hợp lệ: Sai mật khẩu (trong giới hạn) → HTTP 401', () => {
    return frisby
      .post(REST_URL + '/user/login', {
        headers: { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_EP_INVALID },
        body: { email: 'nobody@test.com', password: 'wrongpass' }
      })
      .expect('status', 401)
  })

  it('EP3 - Vùng bị chặn: Vượt quá 10 lần sai → HTTP 429', async () => {
    for (let i = 1; i <= 10; i++) {
      await send(
        REST_URL + '/user/login',
        { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_EP_BLOCKED },
        { email: 'brute@test.com', password: 'wrong' }
      )
    }
    await sendExpect(
      REST_URL + '/user/login',
      { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_EP_BLOCKED },
      { email: 'brute@test.com', password: 'wrong' },
      429,
      { error: String }
    )
  })
})

describe('[Login] Giá trị biên (max = 10)', () => {
  it('BVA1 - Lần thứ 1 (min): Lần sai đầu tiên → HTTP 401 (chưa bị chặn)', () => {
    return frisby
      .post(REST_URL + '/user/login', {
        headers: { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_BVA_1 },
        body: { email: 'bva@test.com', password: 'wrong' }
      })
      .expect('status', 401)
  })

  it('BVA2 - Lần thứ 9 (max - 1): Chưa đạt ngưỡng → HTTP 401', async () => {
    for (let i = 1; i <= 8; i++) {
      await send(
        REST_URL + '/user/login',
        { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_BVA_9 },
        { email: 'bva@test.com', password: 'wrong' }
      )
    }
    await sendExpect(
      REST_URL + '/user/login',
      { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_BVA_9 },
      { email: 'bva@test.com', password: 'wrong' },
      401
    )
  })

  it('BVA3 - Lần thứ 10 (đúng max): Lần cuối được phép → HTTP 401', async () => {
    for (let i = 1; i <= 9; i++) {
      await send(
        REST_URL + '/user/login',
        { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_BVA_10 },
        { email: 'bva@test.com', password: 'wrong' }
      )
    }
    await sendExpect(
      REST_URL + '/user/login',
      { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_BVA_10 },
      { email: 'bva@test.com', password: 'wrong' },
      401
    )
  })

  it('BVA4 - Lần thứ 11 (max + 1): Vượt ngưỡng → HTTP 429 (bị chặn)', async () => {
    for (let i = 1; i <= 10; i++) {
      await send(
        REST_URL + '/user/login',
        { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_BVA_11 },
        { email: 'bva@test.com', password: 'wrong' }
      )
    }
    await sendExpect(
      REST_URL + '/user/login',
      { ...jsonHeader, 'X-Forwarded-For': IP.LOGIN_BVA_11 },
      { email: 'bva@test.com', password: 'wrong' },
      429
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 2. RESET PASSWORD  (max: 5 lần / 15 phút)
// ─────────────────────────────────────────────────────────────────────────────
describe('[Reset Password] Phân vùng tương đương (max = 5 / 15 phút)', () => {
  it('EP1 - Vùng không hợp lệ: Câu trả lời bảo mật sai (trong giới hạn) → HTTP 401', () => {
    return frisby
      .post(REST_URL + '/user/reset-password', {
        headers: { ...jsonHeader, 'X-Forwarded-For': IP.RESET_EP_INVALID },
        body: {
          email: 'jim@juice-sh.op',
          answer: 'wronganswer',
          new: 'NewPass1234!',
          repeat: 'NewPass1234!'
        }
      })
      .expect('status', 401)
  })

  it('EP2 - Vùng bị chặn: Vượt quá 5 lần → HTTP 429', async () => {
    for (let i = 1; i <= 5; i++) {
      await send(
        REST_URL + '/user/reset-password',
        { ...jsonHeader, 'X-Forwarded-For': IP.RESET_EP_BLOCKED },
        {
          email: 'jim@juice-sh.op',
          answer: 'wronganswer',
          new: 'NewPass1234!',
          repeat: 'NewPass1234!'
        }
      )
    }
    await sendExpect(
      REST_URL + '/user/reset-password',
      { ...jsonHeader, 'X-Forwarded-For': IP.RESET_EP_BLOCKED },
      {
        email: 'jim@juice-sh.op',
        answer: 'wronganswer',
        new: 'NewPass1234!',
        repeat: 'NewPass1234!'
      },
      429,
      { error: String }
    )
  })
})

describe('[Reset Password] Giá trị biên (max = 5)', () => {
  it('BVA1 - Lần thứ 1 (min): Lần sai đầu tiên → HTTP 401 (chưa bị chặn)', () => {
    return frisby
      .post(REST_URL + '/user/reset-password', {
        headers: { ...jsonHeader, 'X-Forwarded-For': IP.RESET_BVA_1 },
        body: {
          email: 'jim@juice-sh.op',
          answer: 'wrong',
          new: 'NewPass1234!',
          repeat: 'NewPass1234!'
        }
      })
      .expect('status', 401)
  })

  it('BVA2 - Lần thứ 4 (max - 1): Chưa đạt ngưỡng → HTTP 401', async () => {
    for (let i = 1; i <= 3; i++) {
      await send(
        REST_URL + '/user/reset-password',
        { ...jsonHeader, 'X-Forwarded-For': IP.RESET_BVA_4 },
        {
          email: 'jim@juice-sh.op',
          answer: 'wrong',
          new: 'NewPass1234!',
          repeat: 'NewPass1234!'
        }
      )
    }
    await sendExpect(
      REST_URL + '/user/reset-password',
      { ...jsonHeader, 'X-Forwarded-For': IP.RESET_BVA_4 },
      {
        email: 'jim@juice-sh.op',
        answer: 'wrong',
        new: 'NewPass1234!',
        repeat: 'NewPass1234!'
      },
      401
    )
  })

  it('BVA3 - Lần thứ 5 (đúng max): Lần cuối được phép → HTTP 401', async () => {
    for (let i = 1; i <= 4; i++) {
      await send(
        REST_URL + '/user/reset-password',
        { ...jsonHeader, 'X-Forwarded-For': IP.RESET_BVA_5 },
        {
          email: 'jim@juice-sh.op',
          answer: 'wrong',
          new: 'NewPass1234!',
          repeat: 'NewPass1234!'
        }
      )
    }
    await sendExpect(
      REST_URL + '/user/reset-password',
      { ...jsonHeader, 'X-Forwarded-For': IP.RESET_BVA_5 },
      {
        email: 'jim@juice-sh.op',
        answer: 'wrong',
        new: 'NewPass1234!',
        repeat: 'NewPass1234!'
      },
      401
    )
  })

  it('BVA4 - Lần thứ 6 (max + 1): Vượt ngưỡng → HTTP 429 (bị chặn)', async () => {
    for (let i = 1; i <= 5; i++) {
      await send(
        REST_URL + '/user/reset-password',
        { ...jsonHeader, 'X-Forwarded-For': IP.RESET_BVA_6 },
        {
          email: 'jim@juice-sh.op',
          answer: 'wrong',
          new: 'NewPass1234!',
          repeat: 'NewPass1234!'
        }
      )
    }
    await sendExpect(
      REST_URL + '/user/reset-password',
      { ...jsonHeader, 'X-Forwarded-For': IP.RESET_BVA_6 },
      {
        email: 'jim@juice-sh.op',
        answer: 'wrong',
        new: 'NewPass1234!',
        repeat: 'NewPass1234!'
      },
      429
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// 3. OTP / 2FA  (max: 10 lần / 5 phút)
// ─────────────────────────────────────────────────────────────────────────────
describe('[OTP/2FA] Phân vùng tương đương (max = 10 / 5 phút)', () => {
  it('EP1 - Vùng không hợp lệ: Token sai (trong giới hạn) → HTTP 401', () => {
    return frisby
      .post(REST_URL + '/2fa/verify', {
        headers: { ...jsonHeader, 'X-Forwarded-For': IP.OTP_EP_INVALID },
        body: { tmpToken: 'invalidtoken', totpToken: '000000' }
      })
      .expect('status', 401)
  })

  it('EP2 - Vùng bị chặn: Vượt quá 10 lần → HTTP 429', async () => {
    for (let i = 1; i <= 10; i++) {
      await send(
        REST_URL + '/2fa/verify',
        { ...jsonHeader, 'X-Forwarded-For': IP.OTP_EP_BLOCKED },
        { tmpToken: 'invalidtoken', totpToken: '000000' }
      )
    }
    await sendExpect(
      REST_URL + '/2fa/verify',
      { ...jsonHeader, 'X-Forwarded-For': IP.OTP_EP_BLOCKED },
      { tmpToken: 'invalidtoken', totpToken: '000000' },
      429,
      { error: String }
    )
  })
})

describe('[OTP/2FA] Giá trị biên (max = 10)', () => {
  it('BVA1 - Lần thứ 1 (min): Lần sai đầu tiên → HTTP 401 (chưa bị chặn)', () => {
    return frisby
      .post(REST_URL + '/2fa/verify', {
        headers: { ...jsonHeader, 'X-Forwarded-For': IP.OTP_BVA_1 },
        body: { tmpToken: 'invalid', totpToken: '000000' }
      })
      .expect('status', 401)
  })

  it('BVA2 - Lần thứ 9 (max - 1): Chưa đạt ngưỡng → HTTP 401', async () => {
    for (let i = 1; i <= 8; i++) {
      await send(
        REST_URL + '/2fa/verify',
        { ...jsonHeader, 'X-Forwarded-For': IP.OTP_BVA_9 },
        { tmpToken: 'invalid', totpToken: '000000' }
      )
    }
    await sendExpect(
      REST_URL + '/2fa/verify',
      { ...jsonHeader, 'X-Forwarded-For': IP.OTP_BVA_9 },
      { tmpToken: 'invalid', totpToken: '000000' },
      401
    )
  })

  it('BVA3 - Lần thứ 10 (đúng max): Lần cuối được phép → HTTP 401', async () => {
    for (let i = 1; i <= 9; i++) {
      await send(
        REST_URL + '/2fa/verify',
        { ...jsonHeader, 'X-Forwarded-For': IP.OTP_BVA_10 },
        { tmpToken: 'invalid', totpToken: '000000' }
      )
    }
    await sendExpect(
      REST_URL + '/2fa/verify',
      { ...jsonHeader, 'X-Forwarded-For': IP.OTP_BVA_10 },
      { tmpToken: 'invalid', totpToken: '000000' },
      401
    )
  })

  it('BVA4 - Lần thứ 11 (max + 1): Vượt ngưỡng → HTTP 429 (bị chặn)', async () => {
    for (let i = 1; i <= 10; i++) {
      await send(
        REST_URL + '/2fa/verify',
        { ...jsonHeader, 'X-Forwarded-For': IP.OTP_BVA_11 },
        { tmpToken: 'invalid', totpToken: '000000' }
      )
    }
    await sendExpect(
      REST_URL + '/2fa/verify',
      { ...jsonHeader, 'X-Forwarded-For': IP.OTP_BVA_11 },
      { tmpToken: 'invalid', totpToken: '000000' },
      429
    )
  })
})
