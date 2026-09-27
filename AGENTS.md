---
name: design-system-rules
description: Quy định bắt buộc về UI/UX và phong cách thiết kế cho dự án networking-lab.
trigger: always_on
---

# Bắt buộc tuân thủ Design System (UI/UX)
Mỗi khi khởi tạo, chỉnh sửa HTML/CSS hoặc các thành phần giao diện trong dự án này, AI LUÔN LUÔN phải tuân thủ nghiêm ngặt các quy định sau để giữ phong cách hiện đại, tinh tế và đồng nhất trên toàn dự án:

## 1. Không gian màu (Color Palette)
- **Không dùng màu trắng/đen thuần:** Tuyệt đối không dùng `#ffffff` hay `#000000`. Bắt buộc dùng hệ màu trung tính `Slate` của Tailwind.
- **Nền (Background):** Light mode luôn dùng `bg-slate-50`. Dark mode luôn dùng `bg-slate-950`.
- **Thẻ (Cards/Surfaces):** Trên Dark mode, thẻ phải dùng `bg-slate-900` kết hợp viền mỏng `border-slate-800` để tạo chiều sâu.
- **Điểm nhấn (Accents):** Thay vì tô màu phẳng (flat color) gắt, hãy dùng gradient tinh tế (VD: `bg-gradient-to-br from-blue-500 to-indigo-600`) cho logo, icon hoặc nút bấm chính.

## 2. Typography (Nghệ thuật Kiểu chữ)
- **Văn bản/UI chính:** Bắt buộc dùng font sans-serif `Inter`. Linh hoạt độ nặng: `font-extrabold` cho tiêu đề chính, `font-medium` cho văn bản phụ.
- **Code/Technical/Tags:** Bắt buộc dùng font Monospace `Fira Code` cho các nhãn trạng thái, huy hiệu, thông số kỹ thuật.
- **Khoảng cách (Tracking):** Tiêu đề lớn phải ép hẹp khoảng cách (`tracking-tight`). Nhãn phụ/nhãn nhỏ phải in hoa và kéo giãn khoảng cách (`uppercase tracking-widest text-xs`).

## 3. Hiệu ứng, Bố cục & Khoảng trắng
- **Header:** Luôn sử dụng hiệu ứng Glassmorphism (`backdrop-blur-md bg-white/80 dark:bg-slate-900/80`).
- **Khoảng trắng (Whitespace):** Cố ý giữ padding và margin lớn (VD: `gap-20`, `py-24`) giữa các khối nội dung. Không nhồi nhét thành phần UI.
- **Tương tác (Micro-interactions):** Sử dụng class `.transition-all-fast` của dự án. Hover lên thẻ phải nảy nhẹ (`hover:-translate-y-1 hover:shadow-lg`), không đổi màu quá đột ngột.

## 4. Bảo mật dữ liệu (Global Security Rule)
- **TUYỆT ĐỐI ẨN DANH DỮ LIỆU THẬT:** Nếu prompt của người dùng có chứa IP thật, MAC thật, hostname thật của công ty/khách hàng, hoặc dữ liệu nhạy cảm... AI **PHẢI** tự động làm sạch và thay thế bằng dữ liệu giả (dummy data) trước khi tạo ra HTML.
- Thay IP thật bằng IP giả (VD: `10.x.x.x`, `192.168.x.x`, `1.1.1.1`).
- Thay hostname thật bằng tên chung chung (VD: `FW-CORE`, `SW-ACCESS-01`, `R1`).
- Che đi toàn bộ password, token, domain name, VLAN IDs thật. **Không bao giờ** được output raw data nhạy cảm vào file code.

## 5. Cấu trúc mã nguồn Lab (Engine & Templates)
- Bất cứ khi nào được yêu cầu tạo bài Lab mới, AI **PHẢI** đọc qua file `docs/prompt-templates.md` để chọn đúng 1 trong 8 cấu trúc có sẵn (Ví dụ: Protocol Simulator, Troubleshooting, v.v.).
- Bắt buộc tuân thủ các quy tắc bất biến trong template như: cách dùng hàm `clampNodes()`, cách làm nút `Mode Toggle`, và các Quy ước song ngữ Anh-Việt (Bilingual Standards) đã ghi chú trong đó.

## 6. Quy ước Song ngữ (Bilingual Standards)
Khi viết nội dung hiển thị trên UI, bắt buộc pha trộn Anh - Việt theo quy chuẩn Kỹ sư mạng:
- **Tiếng Anh (Giữ nguyên):** Tiêu đề Lab chính (H1), các trạng thái hệ thống (VD: `ONLINE`, `ERR-DISABLE`), nhãn thanh Stepper (VD: `INIT`, `VERIFY`), tên Role/Thiết bị (VD: `Core Switch`), và toàn bộ output CLI/Console. Tuyệt đối không dịch các thuật ngữ chuyên ngành (như Routing, OSPF, Payload, Failover).
- **Tiếng Việt:** Mô tả chi tiết, nội dung giải thích các bước, tiêu đề phụ, và các phần phân tích. Văn phong phải chuyên nghiệp, súc tích.
