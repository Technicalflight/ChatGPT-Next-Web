import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX, ModelProvider } from "../constant";

// 定义一个包含错误计数的类型
type IpRecord = {
  count: number;
};
// 用来记录错误次数的Map，键为IP地址，值为IpRecord
const ipErrorCountMap = new Map<string, IpRecord>();

// 获取清理间隔时间（毫秒），从环境变量中读取，缺省为 1 天（86400000 毫秒）
const serverConfig = getServerSideConfig();
const CLEAN_INTERVAL = serverConfig.cleanIPBannerInterval;

// 错误次数限制，缺省为 10
const ERROR_LIMIT = serverConfig.errorLimitIPBanner;

// 设置定时器定期清理IP记录
setInterval(() => {
  ipErrorCountMap.clear();
  console.log("[Cleanup] Cleared all IP records.");
}, CLEAN_INTERVAL);


function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isApiKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    accessCode: isApiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isApiKey ? token : "",
  };
}

export function auth(req: NextRequest, modelProvider: ModelProvider) {
  const authToken = req.headers.get("Authorization") ?? "";

  // check if it is openai api key or user token
  const { accessCode, apiKey } = parseApiKey(authToken);

  const hashedCode = md5.hash(accessCode ?? "").trim();

  const serverConfig = getServerSideConfig();
  const userIP = getIP(req) || "unknown";
  // console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] got access code:", accessCode);
  // console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", userIP);
  console.log("[Time] ", new Date().toLocaleString());

  // 获取 enableIPBanner 环境变量，如果未设置或为 0，则不开启 IP 拒绝模式
  const enableIPBanner = serverConfig.enableIPBanner;
  if (enableIPBanner) {
    const ipRecord = ipErrorCountMap.get(userIP);

    // 检查该IP的错误次数是否达到限制
    if (ipRecord && ipRecord.count >= ERROR_LIMIT) {
      console.log(`[IP Banner] ${userIP} has reached the error limit.`);
      return {
        error: true,
        msg: `You have made too many incorrect attempts. Your IP (${userIP}) has been blacklisted. Please contact the administrator to have it unblocked.`,
      };
    }
  }

  if (serverConfig.needCode && !serverConfig.codes.has(hashedCode) && !apiKey) {
    if (enableIPBanner) {
      const ipRecord = ipErrorCountMap.get(userIP);

      if (ipRecord) {
        // 增加错误次数
        ipRecord.count += 1;
        ipErrorCountMap.set(userIP, ipRecord);
      } else {
        // 记录新的错误次数
        ipErrorCountMap.set(userIP, { count: 1 });
      }
      console.log(`[Auth] wrong access code from IP ${userIP}, count: ${ipErrorCountMap.get(userIP)?.count}`);
    }
    return {
      error: true,
      msg: !accessCode ? "empty access code" : "wrong access code, don't try to crack the access code, your IP has been record: " + userIP,
    };
  }

  if (serverConfig.hideUserApiKey && !!apiKey) {
    return {
      error: true,
      msg: "you are not allowed to access with your own api key",
    };
  }

  // Reset the error count on successful auth
  if (enableIPBanner && ipErrorCountMap.has(userIP)) {
    ipErrorCountMap.delete(userIP);
  }

  // if user does not provide an api key, inject system api key
  if (!apiKey) {
    // const serverConfig = getServerSideConfig();

    // const systemApiKey =
    //   modelProvider === ModelProvider.GeminiPro
    //     ? serverConfig.googleApiKey
    //     : serverConfig.isAzure
    //     ? serverConfig.azureApiKey
    //     : serverConfig.apiKey;

    let systemApiKey: string | undefined;

    switch (modelProvider) {
      case ModelProvider.GeminiPro:
        systemApiKey = serverConfig.googleApiKey;
        break;
      case ModelProvider.Claude:
        systemApiKey = serverConfig.anthropicApiKey;
        break;
      case ModelProvider.GPT:
      default:
        if (serverConfig.isAzure) {
          systemApiKey = serverConfig.azureApiKey;
        } else {
          systemApiKey = serverConfig.apiKey;
        }
    }

    if (systemApiKey) {
      console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${systemApiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }

  return {
    error: false,
  };
}
