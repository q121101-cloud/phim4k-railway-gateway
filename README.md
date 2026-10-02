# 🎬 Phim4K Railway Streaming Gateway

Cụm Gateway trung gian phục vụ streaming video tốc độ cao theo mô hình **Hugging Face Hub (Fake `.pth`) + Railway.com + HMAC-SHA256 Signed Token**, tái hiện lại chính xác kiến trúc phân phối media của **4ke**.

---

## 🚀 Tính Năng Nổi Bật

1. **Chuẩn Endpoint 4ke:** Hỗ trợ trực tiếp định dạng URL:
   ```http
   GET /:fileId?phim={phim_hash}&4k={secret_salt}
   ```
2. **Xác thực HMAC Token:** Xác thực chữ ký `phim` kết hợp `4k` salt chống việc bị leech trộm link hoặc crawl hàng loạt.
3. **Tiết kiệm 100% chi phí băng thông Egress (`STREAM_MODE=redirect`):**
   - Trả về mã lệnh `HTTP 302 Found` trỏ trực tiếp đến CDN Google Cloud Singapore của Hugging Face (`x-hf-cdn-pop: sin1`).
   - Server Railway chỉ tốn vài bytes header, không gánh tải video nặng hàng chục GB.
4. **Chế độ Reverse Proxy Stream (`STREAM_MODE=proxy`):**
   - Tự động ghi đè `Content-Type: video/mp4`.
   - Inject header `Access-Control-Allow-Origin: *` phá bỏ mọi rào cản CORS trên trình duyệt web.
   - Hỗ trợ đầy đủ chuẩn HTTP Range Requests RFC 7233 (`206 Partial Content`) để tua video tức thì.
5. **API Ký Link Tự Động:** Endpoint `/api/sign?fileId={fileId}` giúp sinh ngay link xem phim có chữ ký chuẩn.

---

## 🛠️ Hướng Dẫn Triển Khai Lên Railway.com

1. Truy cập [railway.com](https://railway.com) và đăng nhập bằng tài khoản GitHub của bạn.
2. Bấm **New Project** $\rightarrow$ Chọn **Deploy from GitHub repo** $\rightarrow$ Chọn repository `phim4k-railway-gateway`.
3. Vào tab **Variables** trên Railway Dashboard và cấu hình:
   - `HF_REPO`: `username-cua-ban/ten-repo-tren-hf`
   - `SECRET_SALT`: `95bd6bf2` (hoặc mã salt tùy chỉnh của bạn)
   - `STREAM_MODE`: `redirect` (khuyên dùng) hoặc `proxy`
   - `HF_TOKEN`: *(Chỉ điền nếu repo trên Hugging Face của bạn để chế độ Private)*
4. Vào tab **Settings** $\rightarrow$ **Networking** $\rightarrow$ Bấm **Generate Domain** để nhận đường link public có dạng:
   ```
   https://phim4k-gateway-production.up.railway.app
   ```

---

## 📡 Hướng Dẫn Sử Dụng API

### 1. Sinh link xem phim có chữ ký (Kèm HMAC Token)
```bash
curl "https://your-domain.up.railway.app/api/sign?fileId=my_movie_4k"
```
**Kết quả phản hồi:**
```json
{
  "fileId": "my_movie_4k",
  "signedUrl": "https://your-domain.up.railway.app/my_movie_4k?phim=540c749ebc90530e9d6d538e1e7fae29&4k=95bd6bf2",
  "mode": "redirect",
  "targetHfUrl": "https://huggingface.co/username/repo/resolve/main/my_movie_4k.pth"
}
```

### 2. Phát trực tiếp trên Web Player hoặc VLC
Chèn đường dẫn `signedUrl` vừa sinh vào bất kỳ trình phát nào:
```html
<video controls src="https://your-domain.up.railway.app/my_movie_4k?phim=...&4k=95bd6bf2"></video>
```

---

## 🔒 Bản Quyền & Giấy Phép
Dự án được phân phối dưới giấy phép MIT License.
