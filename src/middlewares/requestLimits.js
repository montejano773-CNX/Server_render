import rateLimit from "express-rate-limit";

function envInt(name, fallback, min, max) {
  const value = Number.parseInt(process.env[name] || "", 10);
  if (!Number.isFinite(value)) return fallback;
  return Math.min(Math.max(value, min), max);
}

const MAX_CONCURRENT_REQUESTS = envInt(
  "MAX_CONCURRENT_REQUESTS",
  8,
  1,
  100,
);
const MAX_CONCURRENT_REPORTS = envInt(
  "MAX_CONCURRENT_REPORTS",
  2,
  1,
  MAX_CONCURRENT_REQUESTS,
);
const MAX_REQUEST_QUEUE = envInt("MAX_REQUEST_QUEUE", 20, 0, 500);
const REQUEST_QUEUE_TIMEOUT_MS = envInt(
  "REQUEST_QUEUE_TIMEOUT_MS",
  5000,
  500,
  60000,
);

let activeRequests = 0;
let activeReports = 0;
const waitingRequests = [];

function isReportRequest(req) {
  return String(req.path || "").startsWith("/relatorios/");
}

function canStart(item) {
  if (activeRequests >= MAX_CONCURRENT_REQUESTS) return false;
  return !item.isReport || activeReports < MAX_CONCURRENT_REPORTS;
}

function drainQueue() {
  while (waitingRequests.length > 0) {
    const index = waitingRequests.findIndex(canStart);
    if (index < 0) return;

    const [item] = waitingRequests.splice(index, 1);
    clearTimeout(item.timer);

    if (item.res.destroyed || item.res.writableEnded) continue;
    startRequest(item);
  }
}

function startRequest(item) {
  if (item.onQueuedClose) {
    item.res.removeListener("close", item.onQueuedClose);
  }

  activeRequests += 1;
  if (item.isReport) activeReports += 1;

  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    activeRequests = Math.max(0, activeRequests - 1);
    if (item.isReport) activeReports = Math.max(0, activeReports - 1);
    drainQueue();
  };

  item.res.once("finish", release);
  item.res.once("close", release);
  item.next();
}

export function limitConcurrentRequests(req, res, next) {
  if (req.method === "OPTIONS" || req.path === "/health") return next();

  const item = {
    req,
    res,
    next,
    isReport: isReportRequest(req),
    timer: null,
    onQueuedClose: null,
  };

  if (canStart(item)) {
    startRequest(item);
    return;
  }

  if (waitingRequests.length >= MAX_REQUEST_QUEUE) {
    res.set("Retry-After", "5");
    return res.status(503).json({
      ok: false,
      error: "Servidor ocupado. Tente novamente em alguns segundos.",
    });
  }

  item.timer = setTimeout(() => {
    const index = waitingRequests.indexOf(item);
    if (index >= 0) waitingRequests.splice(index, 1);
    res.removeListener("close", item.onQueuedClose);

    if (!res.headersSent && !res.writableEnded) {
      res.set("Retry-After", "5");
      res.status(503).json({
        ok: false,
        error: "Servidor ocupado. Tente novamente em alguns segundos.",
      });
    }
  }, REQUEST_QUEUE_TIMEOUT_MS);

  item.onQueuedClose = () => {
    const index = waitingRequests.indexOf(item);
    if (index >= 0) waitingRequests.splice(index, 1);
    clearTimeout(item.timer);
  };

  res.once("close", item.onQueuedClose);
  waitingRequests.push(item);
}

const reportRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: envInt("REPORTS_PER_MINUTE", 10, 1, 120),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.authUser.id,
  message: {
    ok: false,
    error: "Muitos relatórios em pouco tempo. Aguarde um minuto e tente novamente.",
  },
});

const mutationRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: envInt("MUTATIONS_PER_MINUTE", 30, 1, 300),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.authUser.id,
  message: {
    ok: false,
    error: "Muitas alterações em pouco tempo. Aguarde um minuto e tente novamente.",
  },
});

export function limitAuthenticatedUser(req, res, next) {
  if (isReportRequest(req)) return reportRateLimiter(req, res, next);

  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    return mutationRateLimiter(req, res, next);
  }

  return next();
}
