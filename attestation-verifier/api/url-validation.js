const DEFAULT_KMS_ALLOWED_HOSTS =
  "phala\\.network$|^localhost$|^127\\.0\\.0\\.1$";
const DEFAULT_NODE_ALLOWED_HOSTS =
  "^\\d+\\.\\d+\\.\\d+\\.\\d+$|^localhost$|^127\\.0\\.0\\.1$";

export function parseAllowedHosts(rawValue, fallbackValue) {
  return (rawValue || fallbackValue)
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function hostMatches(host, patterns, caseInsensitive = true) {
  return patterns.some((pattern) =>
    new RegExp(pattern, caseInsensitive ? "i" : "").test(host)
  );
}

export function validateKmsUrl(url, allowedHostPatterns) {
  const patterns =
    allowedHostPatterns ??
    parseAllowedHosts(undefined, DEFAULT_KMS_ALLOWED_HOSTS);
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid KMS URL");
  }
  if (
    parsed.protocol !== "https:" &&
    parsed.hostname !== "localhost" &&
    parsed.hostname !== "127.0.0.1"
  ) {
    throw new Error("KMS URL must use HTTPS (except localhost)");
  }
  const host = parsed.hostname.toLowerCase();
  if (!hostMatches(host, patterns, true)) {
    throw new Error(
      "KMS URL host not in allowed list (phala.network, localhost). Set KMS_ALLOWED_HOSTS to override."
    );
  }
}

export function validateNodeUrl(url, allowedHostPatterns) {
  const patterns =
    allowedHostPatterns ??
    parseAllowedHosts(undefined, DEFAULT_NODE_ALLOWED_HOSTS);
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid node URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Node URL must use HTTP or HTTPS");
  }
  const host = parsed.hostname.toLowerCase();
  if (!hostMatches(host, patterns, false)) {
    throw new Error(
      "Node URL host not in allowed list (IP addresses, localhost). Set NODE_ALLOWED_HOSTS to override."
    );
  }
}

export const defaults = {
  DEFAULT_KMS_ALLOWED_HOSTS,
  DEFAULT_NODE_ALLOWED_HOSTS,
};
