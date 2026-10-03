/**
 * ========================================================================================
 * RAILWAY.COM STREAMING GATEWAY SERVER (CHUẨN KIẾN TRÚC 4KE - MULTI-REPO POOL READY)
 * ========================================================================================
 * Chức năng:
 * 1. Tiếp nhận request dạng 4ke: GET /:fileId?phim={phim}&4k={4k}&exp={exp}
 * 2. Xác thực HMAC-SHA256 Token / MD5 signature chống leech link kèm TTL 4 tiếng.
 * 3. Chế độ 1 (Khuyên dùng): 302/307 Redirect sang Hugging Face CDN (0Đ băng thông Railway).
 * 4. Chế độ 2: Reverse Proxy Stream, ghi đè Content-Type thành video/mp4 và inject CORS *.
 * 5. Hỗ trợ chuẩn HTTP Range RFC 7233 (206 Partial Content) để tua video mượt mà.
 * 6. MULTI-REPO POOL & REPO_MAP DYNAMIC SYNC:
 *    - Tự động nhận Webhook Push từ phim4k-uploader: POST /api/repo-map (Upsert/Delete/Bulk).
 *    - Persistent local caching: Ghi nhớ danh bạ ánh xạ vào repo_map_cache.json chống mất mát khi reboot.
 *    - Tier 3 Self-Healing Auto-Discovery: Tự động dò tìm repository chứa file nếu cache miss.
 * ========================================================================================
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;
const CACHE_FILE = path.join(__dirname, 'repo_map_cache.json');

// Hàm đọc danh bạ REPO_MAP từ file cache bền vững hoặc biến môi trường
function loadInitialRepoMap() {
  let map = {};
  if (fs.existsSync(CACHE_FILE)) {
    try {
      const content = fs.readFileSync(CACHE_FILE, 'utf-8');
      map = JSON.parse(content);
      console.log(`[✓] Đã nạp ${Object.keys(map).length} mapping từ disk cache '${CACHE_FILE}'`);
    } catch (err) {
      console.warn(`[!] Không thể nạp disk cache '${CACHE_FILE}': ${err.message}`);
    }
  }
  if (process.env.REPO_MAP) {
    try {
      const envMap = JSON.parse(process.env.REPO_MAP);
      map = { ...map, ...envMap };
    } catch (err) {
      console.warn(`[!] Lỗi parse REPO_MAP từ env: ${err.message}`);
    }
  }
  return map;
}

// Lưu REPO_MAP ra file cache an toàn
function saveRepoMapToDisk(map) {
  try {
    const tempFile = `${CACHE_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tempFile, JSON.stringify(map, null, 2), 'utf-8');
    fs.renameSync(tempFile, CACHE_FILE);
  } catch (err) {
    console.error(`[-] Lỗi lưu repo_map_cache.json: ${err.message}`);
  }
}

// Cấu hình môi trường (Cấu hình trên Dashboard Railway)
const CONFIG = {
  // Hugging Face Repo mặc định chứa file .pth
  HF_REPO: process.env.HF_REPO || 'q121101/ai-weights-v1',
  // Hugging Face Token (Nếu repo ở chế độ Private)
  HF_TOKEN: process.env.HF_TOKEN || '',
  // Khóa bí mật ký HMAC Token (Secret Key)
  SECRET_SALT: process.env.SECRET_SALT || '95bd6bf2',
  // Chế độ: 'redirect' (tiết kiệm băng thông Railway) hoặc 'proxy' (ghi đè MIME header)
  STREAM_MODE: process.env.STREAM_MODE || 'redirect',
  // Danh bạ ánh xạ File ID -> Hugging Face Repo / URL (Tự động cập nhật real-time)
  REPO_MAP: loadInitialRepoMap(),
  // Danh sách các repo khả dụng trong cụm để Auto-Discovery khi cache miss
  KNOWN_REPOS: process.env.HF_REPOS_POOL
    ? process.env.HF_REPOS_POOL.split(',').map(r => r.trim()).filter(Boolean)
    : ['q121101/ai-weights-v1', 'user2/movie-vault-01', 'user3/cinema-vault-02'],
  AUTO_DISCOVERY: process.env.AUTO_DISCOVERY !== 'false'
};

// Cho phép CORS toàn cục
app.use(cors({
  origin: '*',
  methods: ['GET', 'HEAD', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Range', 'Authorization', 'Content-Type', 'Accept', 'Origin']
}));

// Hỗ trợ parse JSON cho Webhook Sync
app.use(express.json({ limit: '10mb' }));

// Tắt thông tin server để tăng tính bảo mật
app.disable('x-powered-by');

/**
 * Hàm xác thực Secret Authorization cho các API Admin & Webhook
 */
function verifyAdminAuth(req) {
  const authHeader = req.headers.authorization || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : '';
  const secretQuery = req.query.secret || (req.body && req.body.secret);
  return bearerToken === CONFIG.SECRET_SALT || secretQuery === CONFIG.SECRET_SALT;
}

/**
 * Hàm tính toán chữ ký xác thực chuẩn 4ke & Giới hạn thời gian (TTL 4 tiếng):
 * phim = MD5(fileId + SECRET_SALT + exp)
 */
function verifySignature(fileId, phim, fourK, exp) {
  if (!phim || !fourK) return { valid: false, reason: 'missing_params' };

  // Kiểm tra salt 4k
  if (fourK.toLowerCase() !== CONFIG.SECRET_SALT.toLowerCase()) {
    return { valid: false, reason: 'invalid_salt' };
  }

  const nowSec = Math.floor(Date.now() / 1000);

  // 1. Kiểm tra tham số hết hạn (exp - Giới hạn 4 tiếng)
  if (exp) {
    const expNum = parseInt(exp, 10);
    if (isNaN(expNum) || nowSec > expNum) {
      return { valid: false, reason: 'expired' };
    }
    // Xác thực HMAC-MD5 với exp
    const expectedHmacWithExp = crypto.createHash('md5').update(`${fileId}:${CONFIG.SECRET_SALT}:${exp}`).digest('hex').toLowerCase();
    if (phim.toLowerCase() === expectedHmacWithExp) {
      return { valid: true };
    }
  }

  // 2. Tương thích ngược: kiểm tra HMAC-MD5 không exp
  const expectedHmac = crypto.createHash('md5').update(`${fileId}:${CONFIG.SECRET_SALT}`).digest('hex').toLowerCase();
  if (phim.toLowerCase() === expectedHmac) return { valid: true };

  // 3. Phim4K legacy MD5(fileId)
  const expectedMd5Direct = crypto.createHash('md5').update(fileId).digest('hex').toLowerCase();
  if (phim.toLowerCase() === expectedMd5Direct) return { valid: true };

  return { valid: false, reason: 'invalid_signature' };
}

/**
 * Sinh link xem phim có chữ ký và giới hạn thời gian (Mặc định 4 tiếng):
 */
function generateSignedUrl(baseUrl, fileId, ttlHours = 4) {
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + Math.floor(ttlHours * 3600);
  const phim = crypto.createHash('md5').update(`${fileId}:${CONFIG.SECRET_SALT}:${expSec}`).digest('hex');
  return `${baseUrl.replace(/\/+$/, '')}/${fileId}?phim=${phim}&4k=${CONFIG.SECRET_SALT}&exp=${expSec}`;
}

// ========================================================================================
// REPO_MAP MANAGEMENT & SYNCHRONIZATION WEBHOOK ENDPOINTS
// ========================================================================================

/**
 * Webhook nhận đồng bộ danh bạ từ phim4k-uploader:
 * POST /api/repo-map
 * Headers: Authorization: Bearer <SECRET_SALT>
 * Body:
 *   - Upsert đơn: {"action": "upsert", "file_id": "...", "upstream_url": "..."}
 *   - Delete đơn: {"action": "delete", "file_id": "..."}
 *   - Bulk sync:  {"action": "bulk", "repo_map": { "id1": "url1", ... }}
 */
app.post('/api/repo-map', (req, res) => {
  if (!verifyAdminAuth(req)) {
    return res.status(401).json({ error: '401 Unauthorized', message: 'Secret salt hoặc Bearer token không chính xác.' });
  }

  const { action = 'upsert', file_id, upstream_url, repo_map } = req.body;

  if (action === 'bulk' && repo_map && typeof repo_map === 'object') {
    CONFIG.REPO_MAP = { ...CONFIG.REPO_MAP, ...repo_map };
    saveRepoMapToDisk(CONFIG.REPO_MAP);
    console.log(`[✓] [BULK_SYNC] Đã đồng bộ ${Object.keys(repo_map).length} mapping. Tổng hiện tại: ${Object.keys(CONFIG.REPO_MAP).length}`);
    return res.json({
      success: true,
      action: 'bulk',
      synced_items: Object.keys(repo_map).length,
      total_items: Object.keys(CONFIG.REPO_MAP).length
    });
  }

  if (action === 'upsert') {
    if (!file_id || !upstream_url) {
      return res.status(400).json({ error: 'Missing file_id or upstream_url parameter' });
    }
    CONFIG.REPO_MAP[file_id] = upstream_url;
    // Cũng ánh xạ cả file_id.pth nếu cần
    if (!file_id.endsWith('.pth')) {
      CONFIG.REPO_MAP[`${file_id}.pth`] = upstream_url;
    }
    saveRepoMapToDisk(CONFIG.REPO_MAP);
    console.log(`[✓] [REPO_MAP_UPSERT] Đã cập nhật mapping '${file_id}' -> '${upstream_url}'`);
    return res.json({
      success: true,
      action: 'upsert',
      file_id,
      upstream_url,
      total_items: Object.keys(CONFIG.REPO_MAP).length
    });
  }

  if (action === 'delete') {
    if (!file_id) {
      return res.status(400).json({ error: 'Missing file_id parameter' });
    }
    delete CONFIG.REPO_MAP[file_id];
    delete CONFIG.REPO_MAP[`${file_id}.pth`];
    saveRepoMapToDisk(CONFIG.REPO_MAP);
    console.log(`[✓] [REPO_MAP_DELETE] Đã xóa mapping '${file_id}'`);
    return res.json({
      success: true,
      action: 'delete',
      file_id,
      total_items: Object.keys(CONFIG.REPO_MAP).length
    });
  }

  res.status(400).json({ error: `Hành động không hợp lệ: '${action}'` });
});

/**
 * API xem danh bạ ánh xạ REPO_MAP hiện tại
 */
app.get('/api/repo-map', (req, res) => {
  if (!verifyAdminAuth(req)) {
    return res.status(401).json({ error: '401 Unauthorized' });
  }
  res.json({
    total_items: Object.keys(CONFIG.REPO_MAP).length,
    repo_map: CONFIG.REPO_MAP
  });
});

/**
 * Thống kê tình trạng cụm kho lưu trữ & Gateway
 */
app.get('/api/repo-map/stats', (req, res) => {
  res.json({
    status: 'healthy',
    mode: CONFIG.STREAM_MODE,
    total_mappings: Object.keys(CONFIG.REPO_MAP).length,
    default_hf_repo: CONFIG.HF_REPO,
    known_repos: CONFIG.KNOWN_REPOS,
    auto_discovery: CONFIG.AUTO_DISCOVERY,
    uptime_sec: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

/**
 * Health check cho Railway Deployment Monitor
 */
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    mode: CONFIG.STREAM_MODE,
    mappings_count: Object.keys(CONFIG.REPO_MAP).length,
    time: new Date().toISOString()
  });
});

/**
 * API sinh link xem phim (Dùng cho Admin / CMS web phim)
 */
app.get('/api/sign', (req, res) => {
  const { fileId, ttl } = req.query;
  if (!fileId) {
    return res.status(400).json({ error: 'Missing fileId query parameter' });
  }

  const host = req.get('host');
  const protocol = req.protocol;
  const baseUrl = `${protocol}://${host}`;
  const ttlHours = ttl ? parseFloat(ttl) : 4;
  const signedUrl = generateSignedUrl(baseUrl, fileId, ttlHours);

  let targetHfUrl = CONFIG.REPO_MAP[fileId];
  if (!targetHfUrl) {
    const filename = fileId.endsWith('.pth') ? fileId : `${fileId}.pth`;
    targetHfUrl = `https://huggingface.co/${CONFIG.HF_REPO}/resolve/main/${filename}`;
  }

  res.json({
    fileId,
    signedUrl,
    expiresInHours: ttlHours,
    mode: CONFIG.STREAM_MODE,
    targetHfUrl
  });
});

/**
 * Hàm Auto-Discovery (Tier 3 Fallback): Khi cache miss, probe nhanh danh sách known repos
 */
async function autoDiscoverUpstreamUrl(fileId) {
  const filename = fileId.endsWith('.pth') ? fileId : `${fileId}.pth`;

  // Kiểm tra repo mặc định trước
  const reposToProbe = [CONFIG.HF_REPO, ...CONFIG.KNOWN_REPOS.filter(r => r !== CONFIG.HF_REPO)];

  for (const repo of reposToProbe) {
    const probeUrl = `https://huggingface.co/${repo}/resolve/main/${filename}`;
    try {
      const resp = await axios.head(probeUrl, {
        timeout: 2500,
        maxRedirects: 3,
        validateStatus: status => status === 200 || status === 302 || status === 307
      });
      if (resp.status === 200 || resp.status === 302 || resp.status === 307) {
        console.log(`[✓] [AUTO_DISCOVERY] Tìm thấy file '${filename}' tại repo '${repo}'! Ghi nhớ vào cache.`);
        CONFIG.REPO_MAP[fileId] = probeUrl;
        CONFIG.REPO_MAP[filename] = probeUrl;
        saveRepoMapToDisk(CONFIG.REPO_MAP);
        return probeUrl;
      }
    } catch (e) {
      // Tiếp tục dò repo tiếp theo
    }
  }
  return null;
}

/**
 * CORE ENDPOINT: GET /:fileId?phim=...&4k=...&exp=... (Endpoint chuẩn của 4ke + TTL 4h)
 */
app.get('/:fileId', async (req, res) => {
  const { fileId } = req.params;
  const { phim, fourK, '4k': fourKAlt, exp, mode } = req.query;
  const activeFourK = fourK || fourKAlt;

  // 1. Xác thực Chữ Ký / Token & Hạn 4 tiếng
  const authResult = verifySignature(fileId, phim, activeFourK, exp);
  if (!authResult || !authResult.valid) {
    const isExpired = authResult && authResult.reason === 'expired';
    return res.status(403).json({
      error: '403 Forbidden',
      message: isExpired
        ? 'Đường link này đã hết hạn sau 4 tiếng (Link expired after 4 hours). Vui lòng tải lại link mới từ dashboard.'
        : 'Chữ ký token (phim hoặc 4k) không hợp lệ.'
    });
  }

  // 2. Xác định URL đích trên Hugging Face từ REPO_MAP
  let upstreamUrl = CONFIG.REPO_MAP[fileId];

  // Nếu chưa có trong REPO_MAP, kích hoạt Tier 3 Self-Healing Auto-Discovery
  if (!upstreamUrl && CONFIG.AUTO_DISCOVERY) {
    upstreamUrl = await autoDiscoverUpstreamUrl(fileId);
  }

  // Fallback cuối cùng: suy diễn từ repo mặc định
  if (!upstreamUrl) {
    const filename = fileId.endsWith('.pth') ? fileId : `${fileId}.pth`;
    upstreamUrl = `https://huggingface.co/${CONFIG.HF_REPO}/resolve/main/${filename}`;
  }

  const currentMode = mode || CONFIG.STREAM_MODE;

  // ====================================================================================
  // CHẾ ĐỘ 1: HTTP 302/307 REDIRECT (TIẾT KIỆM 100% EGRESS CHO RAILWAY - CÁCH 4KE DÙNG)
  // ====================================================================================
  if (currentMode === 'redirect') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    // Chuyển hướng người xem trực tiếp sang CDN Google Cloud Singapore của Hugging Face
    return res.redirect(302, upstreamUrl);
  }

  // ====================================================================================
  // CHẾ ĐỘ 2: REVERSE PROXY STREAMING (GHI ĐÈ MIME TYPE & CHUYỂN TIẾP RANGE REQUEST)
  // ====================================================================================
  try {
    const rangeHeader = req.headers.range;
    const requestHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': '*/*'
    };

    if (CONFIG.HF_TOKEN) {
      requestHeaders['Authorization'] = `Bearer ${CONFIG.HF_TOKEN}`;
    }

    if (rangeHeader) {
      requestHeaders['Range'] = rangeHeader;
    }

    // Gửi request sang Hugging Face CDN
    const upstreamResponse = await axios({
      method: 'GET',
      url: upstreamUrl,
      headers: requestHeaders,
      responseType: 'stream',
      maxRedirects: 5,
      validateStatus: (status) => status >= 200 && status < 400
    });

    // Thiết lập Header phản hồi chuẩn cho video player HTML5
    res.status(upstreamResponse.status);
    res.setHeader('Content-Type', 'video/mp4'); // Ghi đè ép buộc MIME type
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Content-Length, Accept-Ranges');

    if (upstreamResponse.headers['content-range']) {
      res.setHeader('Content-Range', upstreamResponse.headers['content-range']);
    }
    if (upstreamResponse.headers['content-length']) {
      res.setHeader('Content-Length', upstreamResponse.headers['content-length']);
    }

    // Pipe luồng dữ liệu nhị phân về cho trình phát
    upstreamResponse.data.pipe(res);

    upstreamResponse.data.on('error', (err) => {
      console.error('[!] Lỗi Upstream Stream:', err.message);
      if (!res.headersSent) res.status(502).end();
    });

    req.on('close', () => {
      upstreamResponse.data.destroy();
    });

  } catch (err) {
    console.error(`[-] Lỗi Proxy file ${fileId}:`, err.message);
    if (!res.headersSent) {
      res.status(502).json({
        error: '502 Bad Gateway',
        message: 'Không thể kết nối hoặc tải file từ Hugging Face CDN.',
        detail: err.message
      });
    }
  }
});

// Khởi chạy server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(75));
  console.log(` [✓] 4KE RAILWAY MULTI-REPO GATEWAY RUNNING ON PORT : ${PORT}`);
  console.log(` [✓] DEFAULT HF REPOSITORY                         : ${CONFIG.HF_REPO}`);
  console.log(` [✓] INITIAL REPO_MAP MAPPINGS                     : ${Object.keys(CONFIG.REPO_MAP).length}`);
  console.log(` [✓] KNOWN REPOS IN CLUSTER POOL                   : ${CONFIG.KNOWN_REPOS.join(', ')}`);
  console.log(` [✓] DEFAULT STREAM MODE                           : ${CONFIG.STREAM_MODE}`);
  console.log(` [✓] SECRET SALT                                   : ${CONFIG.SECRET_SALT}`);
  console.log('='.repeat(75));
});

module.exports = { app, server, CONFIG };
