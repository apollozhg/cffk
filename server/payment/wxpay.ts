import { parseWxpayConfig, type WxpayConfig } from "@/lib/config-schemas";
import type { PaymentAdapter, PaymentNotifyResult } from "./types";
import type { PaymentProviderKind } from "./registry";

const WXPAY_API = "https://api.mch.weixin.qq.com";
const WXPAY_PROVIDER: PaymentProviderKind = "WXPAY";

function base64(value: ArrayBuffer | Uint8Array<ArrayBuffer>): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Bytes(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function timingSafeStringEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  if (leftBytes.length !== rightBytes.length) return false;
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) difference |= leftBytes[index]! ^ rightBytes[index]!;
  return difference === 0;
}

function normalizedPem(value: string): string {
  const normalized = value.replace(/\\n/g, "\n").trim();
  if (/-----BEGIN RSA PRIVATE KEY-----/.test(normalized)) throw new Error("WXPAY_PRIVATE_KEY_PKCS1");
  return normalized;
}

async function importPrivateKey(pem: string) {
  const body = normalizedPem(pem).replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  return crypto.subtle.importKey("pkcs8", base64Bytes(body), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

async function importPublicKey(pem: string) {
  const body = normalizedPem(pem).replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  return crypto.subtle.importKey("spki", base64Bytes(body), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
}

// 微信支付 API v3 请求签名（WECHATPAY2-SHA256-RSA2048）
// 签名串 = {method}\n{pathWithQuery}\n{timestamp}\n{nonce}\n{body}\n
async function wxpaySign(config: WxpayConfig, method: string, pathWithQuery: string, body: string): Promise<string> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const message = `${method}\n${pathWithQuery}\n${timestamp}\n${nonce}\n${body}\n`;
  const privateKey = await importPrivateKey(config.privateKey);
  const signature = base64(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(message)));
  return `WECHATPAY2-SHA256-RSA2048 mchid="${config.mchid}",nonce_str="${nonce}",signature="${signature}",timestamp="${timestamp}",serial_no="${config.merchantSerialNo}"`;
}

async function wxpayRequest(config: WxpayConfig, method: string, pathWithQuery: string, bodyJson?: unknown): Promise<{ status: number; text: string; json: Record<string, unknown> | null }> {
  const body = bodyJson === undefined ? "" : JSON.stringify(bodyJson);
  const authorization = await wxpaySign(config, method, pathWithQuery, body);
  const response = await fetch(`${WXPAY_API}${pathWithQuery}`, {
    method,
    headers: {
      Authorization: authorization,
      Accept: "application/json",
      ...(bodyJson === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: bodyJson === undefined ? undefined : body,
  });
  const text = await response.text();
  let json: Record<string, unknown> | null = null;
  try {
    const parsed = text ? JSON.parse(text) : null;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) json = parsed as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: response.status, text, json };
}

// 回调解密：AEAD_AES_256_GCM，密钥为 APIv3 密钥
async function decryptResource(config: WxpayConfig, resource: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (resource.algorithm !== "AEAD_AES_256_GCM" || typeof resource.ciphertext !== "string" || !resource.ciphertext || typeof resource.nonce !== "string" || !resource.nonce) {
    throw new Error("WXPAY_CALLBACK_INVALID");
  }
  const apiV3KeyBytes = new TextEncoder().encode(config.apiV3Key);
  if (apiV3KeyBytes.length !== 32) throw new Error("WXPAY_API_V3_KEY_INVALID");
  const aesKey = await crypto.subtle.importKey("raw", apiV3KeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const additionalData = typeof resource.associated_data === "string" && resource.associated_data ? new TextEncoder().encode(resource.associated_data) : undefined;
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64Bytes(resource.nonce), additionalData }, aesKey, base64Bytes(resource.ciphertext));
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("WXPAY_CALLBACK_INVALID");
  return parsed as Record<string, unknown>;
}

function tradeStateStatus(state: string): "PENDING" | "PAID" | "FAILED" {
  if (state === "SUCCESS") return "PAID";
  if (state === "CLOSED" || state === "REVOKED" || state === "PAYERROR") return "FAILED";
  return "PENDING";
}

function amountTotal(amount: unknown): number | undefined {
  if (amount && typeof amount === "object" && !Array.isArray(amount)) {
    const value = (amount as Record<string, unknown>).total;
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return undefined;
}

function result(provider: PaymentProviderKind, values: Partial<PaymentNotifyResult> & Pick<PaymentNotifyResult, "verified" | "status" | "message">): PaymentNotifyResult {
  return { provider, ...values };
}

export function createWxpayAdapter(configJson: string): PaymentAdapter {
  const config = parseWxpayConfig(configJson);
  return {
    // Native 扫码下单：返回 code_url，由前台 PaymentQrCode 渲染二维码
    create: async (input) => {
      const path = "/v3/pay/transactions/native";
      const body = {
        appid: config.appId,
        mchid: config.mchid,
        description: input.subject.slice(0, 127),
        out_trade_no: input.orderNo,
        notify_url: input.notifyUrl,
        amount: { total: input.amount, currency: "CNY" },
      };
      const { status, json } = await wxpayRequest(config, "POST", path, body);
      if (status !== 200 || !json || typeof json.code_url !== "string" || !json.code_url) throw new Error("WXPAY_CREATE_FAILED");
      return { mode: "qr", qrCode: json.code_url };
    },
    // 回调：验签（微信支付公钥）+ AES-256-GCM 解密 + 订单金额核对（金额核对由回调服务统一完成）
    verify: async ({ rawBody = "", headers }) => {
      const timestamp = headers?.get("Wechatpay-Timestamp") ?? "";
      const nonce = headers?.get("Wechatpay-Nonce") ?? "";
      const signature = headers?.get("Wechatpay-Signature") ?? "";
      if (!timestamp || !nonce || !signature || !rawBody) {
        return result(WXPAY_PROVIDER, { verified: false, status: "FAILED", message: "WXPAY_CALLBACK_INVALID" });
      }
      const publicKey = await importPublicKey(config.wxpayPublicKey).catch(() => null);
      if (!publicKey) return result(WXPAY_PROVIDER, { verified: false, status: "FAILED", message: "WXPAY_PUBLIC_KEY_INVALID" });
      const message = `${timestamp}\n${nonce}\n${rawBody}\n`;
      const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, base64Bytes(signature), new TextEncoder().encode(message));
      if (!valid) return result(WXPAY_PROVIDER, { verified: false, status: "FAILED", message: "WXPAY_SIGNATURE_INVALID" });
      let event: Record<string, unknown>;
      try {
        const parsed = JSON.parse(rawBody) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
        event = parsed as Record<string, unknown>;
      } catch {
        return result(WXPAY_PROVIDER, { verified: false, status: "FAILED", message: "WXPAY_CALLBACK_INVALID" });
      }
      const resource = event.resource;
      if (!resource || typeof resource !== "object" || Array.isArray(resource)) {
        return result(WXPAY_PROVIDER, { verified: false, status: "FAILED", message: "WXPAY_CALLBACK_INVALID" });
      }
      let decrypted: Record<string, unknown>;
      try {
        decrypted = await decryptResource(config, resource as Record<string, unknown>);
      } catch {
        return result(WXPAY_PROVIDER, { verified: false, status: "FAILED", message: "WXPAY_CALLBACK_INVALID" });
      }
      const outTradeNo = typeof decrypted.out_trade_no === "string" ? decrypted.out_trade_no : "";
      const transactionId = typeof decrypted.transaction_id === "string" ? decrypted.transaction_id : "";
      const total = amountTotal(decrypted.amount);
      const tradeState = typeof decrypted.trade_state === "string" ? decrypted.trade_state : "";
      if (!outTradeNo || !transactionId || total === undefined) {
        return result(WXPAY_PROVIDER, { verified: false, status: "FAILED", message: "WXPAY_CALLBACK_INVALID" });
      }
      return result(WXPAY_PROVIDER, {
        verified: true,
        orderNo: outTradeNo,
        paymentOrderNo: transactionId,
        amount: total,
        currency: "CNY",
        status: tradeStateStatus(tradeState),
        message: "WXPAY_CALLBACK",
      });
    },
    // 主动查单：按商户订单号查询微信侧交易状态
    query: async ({ orderNo }) => {
      const path = `/v3/pay/transactions/out-trade-no/${encodeURIComponent(orderNo)}?mchid=${encodeURIComponent(config.mchid)}`;
      const { status, json } = await wxpayRequest(config, "GET", path);
      if (status !== 200 || !json || json.out_trade_no !== orderNo) {
        return result(WXPAY_PROVIDER, { verified: false, orderNo, status: "PENDING", message: "WXPAY_QUERY_FAILED" });
      }
      const total = amountTotal(json.amount);
      const tradeState = typeof json.trade_state === "string" ? json.trade_state : "";
      if (total === undefined) return result(WXPAY_PROVIDER, { verified: false, orderNo, status: "PENDING", message: "WXPAY_QUERY_FAILED" });
      return result(WXPAY_PROVIDER, {
        verified: true,
        orderNo,
        paymentOrderNo: typeof json.transaction_id === "string" ? json.transaction_id : undefined,
        amount: total,
        currency: "CNY",
        status: tradeStateStatus(tradeState),
        message: "WXPAY_QUERY",
      });
    },
  };
}
