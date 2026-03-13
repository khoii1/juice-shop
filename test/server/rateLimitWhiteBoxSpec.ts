import sinon from "sinon";
import chai from "chai";
import sinonChai from "sinon-chai";
import * as security from "../../lib/insecurity";
import { resetPassword } from "../../routes/resetPassword";

const expect = chai.expect;
chai.use(sinonChai);

// Tái tạo hàm keyGenerator từ server.ts (inline nên không export được)
const keyGenerator = ({
  headers,
  ip,
}: {
  headers: Record<string, string | undefined>;
  ip: string;
}): string => headers["x-forwarded-for"] ?? ip;

// Nhóm 1: keyGenerator – lỗ hổng bypass rate limit tại /rest/user/reset-password
describe("keyGenerator (rate limit bypass vulnerability)", () => {
  it("WB1 – Có X-Forwarded-For → dùng header, bỏ qua IP thật", () => {
    const result = keyGenerator({
      headers: { "x-forwarded-for": "1.2.3.4" },
      ip: "9.9.9.9",
    });
    expect(result).to.equal("1.2.3.4");
  });

  it("WB2 – Không có X-Forwarded-For → dùng IP thật", () => {
    const result = keyGenerator({ headers: {}, ip: "9.9.9.9" });
    expect(result).to.equal("9.9.9.9");
  });

  it("WB3 – X-Forwarded-For là undefined → dùng IP thật", () => {
    const result = keyGenerator({
      headers: { "x-forwarded-for": undefined },
      ip: "9.9.9.9",
    });
    expect(result).to.equal("9.9.9.9");
  });

  it("WB4 – Hai giá trị X-Forwarded-For khác nhau → rate limiter coi là 2 IP khác nhau", () => {
    const ip1 = keyGenerator({
      headers: { "x-forwarded-for": "10.0.0.1" },
      ip: "9.9.9.9",
    });
    const ip2 = keyGenerator({
      headers: { "x-forwarded-for": "10.0.0.2" },
      ip: "9.9.9.9",
    });
    expect(ip1).to.not.equal(ip2);
  });
});

// Nhóm 2: resetPassword() – kiểm tra các nhánh if/else trong routes/resetPassword.ts
describe("resetPassword() – branch coverage", () => {
  let req: any;
  let res: any;
  let next: any;

  beforeEach(() => {
    req = {
      body: {},
      connection: { remoteAddress: "127.0.0.1" },
    };
    res = {
      status: sinon.stub().returnsThis(),
      send: sinon.spy(),
      json: sinon.spy(),
      __: (str: string) => str,
    };
    next = sinon.spy();
  });

  it("WB5 – Thiếu email và answer → next(Error)", () => {
    req.body = { new: "NewPass1!", repeat: "NewPass1!" };
    resetPassword()(req, res, next);
    expect(next.calledOnce).to.equal(true);
    expect(next.args[0][0]).to.be.instanceOf(Error);
    expect(next.args[0][0].message).to.include("Blocked illegal activity");
  });

  it("WB6 – Có email nhưng thiếu answer → next(Error)", () => {
    req.body = {
      email: "test@juice-sh.op",
      new: "NewPass1!",
      repeat: "NewPass1!",
    };
    resetPassword()(req, res, next);
    expect(next.calledOnce).to.equal(true);
    expect(next.args[0][0]).to.be.instanceOf(Error);
    expect(next.args[0][0].message).to.include("Blocked illegal activity");
  });

  it('WB7 – Thiếu mật khẩu mới → HTTP 401 "Password cannot be empty."', () => {
    req.body = { email: "test@juice-sh.op", answer: "someAnswer" };
    resetPassword()(req, res, next);
    expect(res.status).to.have.been.calledWith(401);
    expect(res.send).to.have.been.calledWith("Password cannot be empty.");
  });

  it('WB8 – Mật khẩu mới là chuỗi "undefined" → HTTP 401 "Password cannot be empty."', () => {
    req.body = {
      email: "test@juice-sh.op",
      answer: "someAnswer",
      new: "undefined",
    };
    resetPassword()(req, res, next);
    expect(res.status).to.have.been.calledWith(401);
    expect(res.send).to.have.been.calledWith("Password cannot be empty.");
  });

  it('WB9 – Mật khẩu mới và nhập lại không khớp → HTTP 401 "New and repeated password do not match."', () => {
    req.body = {
      email: "test@juice-sh.op",
      answer: "someAnswer",
      new: "Password1!",
      repeat: "Password2!",
    };
    resetPassword()(req, res, next);
    expect(res.status).to.have.been.calledWith(401);
    expect(res.send).to.have.been.calledWith(
      "New and repeated password do not match.",
    );
  });
});

// Nhóm 3: security.hmac() – dùng trong resetPassword để hash câu trả lời bảo mật
describe("security.hmac() – hash câu trả lời bảo mật", () => {
  it("WB10 – Cùng input → cùng output (so sánh hash được)", () => {
    expect(security.hmac("SomeAnswer")).to.equal(security.hmac("SomeAnswer"));
  });

  it("WB11 – Phân biệt hoa/thường → bruteforce phải đúng chính xác", () => {
    expect(security.hmac("answer")).to.not.equal(security.hmac("Answer"));
    expect(security.hmac("answer")).to.not.equal(security.hmac("ANSWER"));
  });

  it("WB12 – Output khác plaintext → không lưu câu trả lời rõ trong DB", () => {
    const plain = "MySecretAnswer";
    expect(security.hmac(plain)).to.not.equal(plain);
  });

  it("WB13 – Dùng SHA-256 → output 64 ký tự hex", () => {
    expect(security.hmac("test")).to.match(/^[0-9a-f]{64}$/);
  });
});

// Nhóm 4: security.hash() – dùng trong login để hash mật khẩu trước khi truy vấn DB
describe("security.hash() – hash mật khẩu đăng nhập", () => {
  it("WB14 – Dùng MD5 → output 32 ký tự hex (thuật toán yếu)", () => {
    expect(security.hash("admin123")).to.match(/^[0-9a-f]{32}$/);
  });

  it("WB15 – MD5 có trong rainbow table → dễ bị reverse lookup", () => {
    expect(security.hash("password")).to.equal(
      "5f4dcc3b5aa765d61d8327deb882cf99",
    );
  });

  it("WB16 – Không có salt → cùng mật khẩu cho cùng hash", () => {
    expect(security.hash("admin123")).to.equal(security.hash("admin123"));
  });

  it("WB17 – Phân biệt hoa/thường → bruteforce phải đúng case", () => {
    expect(security.hash("admin123")).to.not.equal(security.hash("Admin123"));
  });
});
