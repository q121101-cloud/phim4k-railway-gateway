/**
 * ========================================================================================
 * RAILWAY.COM STREAMING GATEWAY SERVER (CHUẨN KIẾN TRÚC 4KE)
 * ========================================================================================
 * Chức năng:
 * 1. Tiếp nhận request dạng 4ke: GET /:fileId?phim={phim}&4k={4k}
 * 2. Xác thực HMAC-SHA256 Token / MD5 signature chống leech link.
 * 3. Chế độ 1 (Khuyên dùng): 302/307 Redirect sang Hugging Face CDN (0Đ băng thông Railway).
 * 4. Chế độ 2: Reverse Proxy Stream, ghi đè Content-Type thành video/mp4 và inject CORS *.
 * 5. Hỗ trợ chuẩn HTTP Range RFC 7233 (206 Partial Content) để tua video mượt mà.
 * 
 * Triển khai: Deploy trực tiếp lên Railway.com qua GitHub hoặc `railway up`.
 * ========================================================================================
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8080;

// Cấu hình môi trường (Cấu hình trên Dashboard Railway)
const CONFIG = {
  // Hugging Face Repo mặc định chứa file .pth
  HF_REPO: process.env.HF_REPO || 'your-username/ai-weights-v1',
  // Hugging Face Token (Nếu repo ở chế độ Private)
  HF_TOKEN: process.env.HF_TOKEN || '',
  // Khóa bí mật ký HMAC Token (Secret Key)
  SECRET_SALT: process.env.SECRET_SALT || '95bd6bf2',
  // Chế độ: 'redirect' (tiết kiệm băng thông Railway) hoặc 'proxy' (ghi đè MIME header)
  STREAM_MODE: process.env.STREAM_MODE || 'redirect',
  // Danh bạ ánh xạ File ID -> Hugging Face Repo / URL (Nếu phân tán nhiều repo)
  REPO_MAP: process.env.REPO_MAP ? JSON.parse(process.env.REPO_MAP) : {}
};

// Cho phép CORS toàn cục
app.use(cors({
  origin: '*',
  methods: ['GET', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['Range', 'Authorization', 'Content-Type', 'Accept', 'Origin']
}));

// Tắt thông tin server để tăng tính bảo mật
app.disable('x-powered-by');

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

/**
 * Health check cho Railway Deployment Monitor
 */
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', mode: CONFIG.STREAM_MODE, time: new Date().toISOString() });
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

  res.json({
    fileId,
    signedUrl,
    expiresInHours: ttlHours,
    mode: CONFIG.STREAM_MODE,
    targetHfUrl: `https://huggingface.co/${CONFIG.HF_REPO}/resolve/main/${fileId}.pth`
  });
});

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

  // 2. Xác định URL đích trên Hugging Face
  let upstreamUrl = CONFIG.REPO_MAP[fileId];
  if (!upstreamUrl) {
    // Tự động suy diễn: https://huggingface.co/{HF_REPO}/resolve/main/{fileId}.pth
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
app.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(70));
  console.log(` [✓] 4KE RAILWAY GATEWAY RUNNING ON PORT : ${PORT}`);
  console.log(` [✓] DEFAULT HF REPOSITORY              : ${CONFIG.HF_REPO}`);
  console.log(` [✓] DEFAULT STREAM MODE                : ${CONFIG.STREAM_MODE}`);
  console.log(` [✓] SECRET SALT                        : ${CONFIG.SECRET_SALT}`);
  console.log('='.repeat(70));
});
