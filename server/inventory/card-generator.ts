import { createHash, randomInt } from "node:crypto";
import { eq } from "drizzle-orm";
import { appError } from "@/lib/app-error";
import { env } from "@/server/env";
import { card } from "@/database/drizzle/schema";
import type { createDrizzleDb } from "@/database/drizzle";

/**
 * 后台卡密生成模块（服务端版，与播放器 license.py / gen_keys.py 同算法）。
 *
 * 算法（登记于《08_后台与播放器配置协调约定》#2，改动前必须先登记）：
 *   payload = `${seq:08d}|`（不绑定机器，machine 为空串）
 *   sig     = SHA256(payload + secret).hexdigest()[:8].upper()
 *   core    = seq(8位) + sig(8位) = 16 位大写十六进制
 *   key     = PREFIX-XXXX-XXXX-XXXX
 *
 * 服务端生成默认【不绑定机器】（任何电脑可激活，与现有发卡策略一致）。
 * 签名密钥经环境变量注入（CARD_KEY_CINEVIEW / CARD_KEY_CREATOR），值必须与
 * 播放器 license.py 的 _LOCAL_SECRET 一致，否则客户端无法验证激活。
 * 密钥不入仓库、不入文档、不出现在任何交付物中。
 */

export const CARD_SIGNER_CONFIGS: Record<string, { prefix: string; secretEnvName: string }> = {
  // product_id（CFFK 商品 slug，08 文档 §3 登记）→ 卡密前缀 + 密钥环境变量
  "player-001": { prefix: "CINEVIEW-", secretEnvName: "CARD_KEY_CINEVIEW" },
  "creator-001": { prefix: "CREATOR-", secretEnvName: "CARD_KEY_CREATOR" },
};

export function getCardSignerConfig(productSlug: string) {
  const config = CARD_SIGNER_CONFIGS[productSlug];
  if (!config) appError("CARD_PRODUCT_UNSUPPORTED");
  return config;
}

export function getCardSecret(secretEnvName: string): string {
  const value = (env as unknown as Record<string, string | undefined>)[secretEnvName];
  if (!value) appError("CARD_SIGNER_KEY_NOT_CONFIGURED");
  return value;
}

export function buildCardKey(prefix: string, secret: string, seq: number): string {
  const seqStr = seq.toString().padStart(8, "0");
  const sig = createHash("sha256").update(`${seqStr}|${secret}`).digest("hex").slice(0, 8).toUpperCase();
  const core = `${seqStr}${sig}`;
  return `${prefix}${core.slice(0, 4)}-${core.slice(4, 8)}-${core.slice(8, 12)}-${core.slice(12, 16)}`;
}

/**
 * 生成 count 条不绑定机器的卡密并避开本商品已存在的卡密。
 * seq 使用 8 位随机十进制序号：与本地 keys_seq.txt 序号体系互不依赖，
 * 碰撞概率（1/10^8）可忽略，且入库前按 content 全量查重兜底。
 */
export async function generateUnboundCardKeys(
  db: ReturnType<typeof createDrizzleDb>,
  productId: number,
  count: number,
  prefix: string,
  secret: string,
): Promise<string[]> {
  const existing = await db.select({ content: card.content }).from(card).where(eq(card.productId, productId));
  const used = new Set(existing.map((row) => row.content));
  const keys: string[] = [];
  let attempts = 0;
  const maxAttempts = count * 50 + 500;
  while (keys.length < count && attempts < maxAttempts) {
    attempts += 1;
    const seq = randomInt(0, 100_000_000);
    const key = buildCardKey(prefix, secret, seq);
    if (used.has(key)) continue;
    used.add(key);
    keys.push(key);
  }
  if (keys.length < count) appError("CARD_GENERATE_CONFLICT");
  return keys;
}
