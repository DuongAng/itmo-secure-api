# Kịch bản trả Lab 1 – Защищённый REST API + CI/CD

> 📺 = làm gì trên màn hình · 🗣 = đọc (tiếng Nga) · 💬 = nghĩa tiếng Việt
> Mở sẵn: **repo GitHub** (tab README + tab Actions), **VS Code** (file `app.py`), **Postman** hoặc terminal curl.

---

## 0. Mở đầu
🗣 Первая работа — защищённый REST API с проверками безопасности в CI/CD. Можно показать?
💬 Bài 1 — REST API an toàn có kiểm tra bảo mật trong CI/CD. Em show được không ạ?

*(Nếu trả riêng:* 🗣 Здравствуйте! Зыонг Динь Ань, группа Р3414. Хочу сдать первую работу.*)*

---

## 1. Репозиторий và API
📺 Mở trang README của repo trên GitHub.

🗣 API написан на Python и Flask, код лежит в публичном репозитории на GitHub. Это мини-блог: четыре метода — регистрация, вход, получение постов и создание поста. Два метода защищены и требуют токен.
💬 API viết bằng Python/Flask, để trên GitHub công khai. Là mini-blog: 4 method — đăng ký, đăng nhập, lấy post, tạo post. 2 cái cần token.

---

## 2. Защита от SQLi và XSS
📺 Mở `app.py`, trỏ vào dòng `db.execute("... WHERE username = ?", (username,))`.

🗣 От SQL-инъекций защищают параметризованные запросы: значение передаётся отдельно от текста SQL, строки не склеиваются. Поэтому ввод «' OR 1=1» воспринимается просто как логин.
💬 Chống SQLi bằng query tham số hoá: giá trị truyền riêng khỏi câu SQL, không nối chuỗi. Nên `' OR 1=1` chỉ bị coi là tên đăng nhập.

📺 Trỏ vào dòng `escape(content)`.

🗣 От XSS весь пользовательский текст экранируется функцией escape: теги вроде <script> превращаются в безопасный текст и не выполняются.
💬 Chống XSS: mọi text người dùng được escape, thẻ `<script>` thành text thường, không chạy.

---

## 3. Аутентификация (bcrypt + JWT)
📺 Trỏ vào `bcrypt.hashpw` và decorator `@require_auth`.

🗣 Пароли хранятся только как bcrypt-хэш с солью, в открытом виде — никогда. При входе выдаётся JWT-токен на 60 минут, секрет берётся из переменной окружения. Middleware проверяет токен на защищённых эндпоинтах, без него — ответ 401.
💬 Mật khẩu chỉ lưu dạng bcrypt-hash có salt, không bao giờ để trần. Đăng nhập xong cấp JWT 60 phút, secret lấy từ biến môi trường. Middleware kiểm token ở endpoint bảo vệ, thiếu token → 401.

---

## 4. Демонстрация (Postman / curl)
📺 Gửi request `POST /auth/login` → chỉ vào `token` trong response.

🗣 Вхожу — сервер возвращает JWT-токен.
💬 Đăng nhập — server trả về token JWT.

📺 Gửi `GET /api/data` CÓ header `Authorization: Bearer <token>` → trả dữ liệu.

🗣 С токеном защищённый эндпоинт возвращает данные.
💬 Có token thì endpoint bảo vệ trả dữ liệu.

📺 Gửi lại `GET /api/data` BỎ header token → trả **401**.

🗣 Без токена — доступ запрещён, код 401. Значит аутентификация работает.
💬 Không token → bị chặn, 401. Tức là xác thực hoạt động.

---

## 5. CI/CD pipeline
📺 Mở tab **Actions** của repo, bấm vào lần chạy mới nhất (xanh).

🗣 При каждом push автоматически запускается pipeline: статический анализ кода Bandit, проверка зависимостей pip-audit и тесты. Вот последний запуск — всё зелёное, критических уязвимостей не найдено.
💬 Mỗi lần push, pipeline tự chạy: Bandit phân tích code, pip-audit quét thư viện, và test. Đây là lần chạy mới nhất — xanh hết, không có lỗ hổng nghiêm trọng.

🗣 Это всё по первой работе.
💬 Bài 1 của em vậy thôi ạ.

---

## ❓ Câu hỏi kiểm tra (cô đọc từ PDF)

**1. Почему bcrypt предпочтительнее SHA-256 для паролей?**
🗣 bcrypt медленный и адаптивный, со встроенной солью, поэтому перебор дорогой, а одинаковые пароли дают разные хэши. SHA-256 быстрый — миллиарды попыток в секунду на GPU, и без соли уязвим к готовым таблицам. Для паролей он не подходит.
💬 bcrypt chậm, có salt sẵn → brute-force tốn kém, mật khẩu giống nhau ra hash khác nhau. SHA-256 nhanh, GPU thử tỷ lần/giây, không salt dễ bị rainbow table — không hợp để lưu mật khẩu.

**2. Разница между SAST и DAST?**
🗣 SAST анализирует исходный код, не запуская его — взгляд изнутри. DAST тестирует уже работающее приложение снаружи, как чёрный ящик. У меня в pipeline SAST — это Bandit.
💬 SAST đọc mã nguồn, không chạy app — nhìn từ trong. DAST test app đang chạy từ ngoài, kiểu hộp đen. Trong pipeline của em SAST là Bandit.

**3. Как работает JWT-токен?**
🗣 JWT состоит из трёх частей: заголовок, данные и подпись. В данных — кто пользователь и срок действия. Сервер подписывает токен секретом и при каждом запросе пересчитывает подпись: совпала и срок не вышел — токен подлинный. Сессию на сервере хранить не нужно.
💬 JWT có 3 phần: header, payload, chữ ký. Payload chứa user và hạn dùng. Server ký bằng secret, mỗi request tính lại chữ ký: khớp và chưa hết hạn thì token thật. Không cần lưu session ở server.

**4. Риски, если не проверять сторонние библиотеки?**
🗣 В них могут быть известные уязвимости (CVE) — атака на цепочку поставок. Даже при правильном своём коде уязвимая библиотека может дать выполнение кода или утечку. Поэтому их нужно сканировать и обновлять — у меня это pip-audit.
💬 Thư viện có thể dính CVE — tấn công chuỗi cung ứng. Code mình đúng nhưng thư viện lỗi vẫn bị RCE/lộ dữ liệu. Nên phải quét và cập nhật — của em là pip-audit.

---

## ❓ Câu cô có thể hỏi thêm

**Почему Flask / Python?**
🗣 Это простой и читаемый стек, которого достаточно для учебного API, и под него есть удобные инструменты безопасности — Bandit и pip-audit.
💬 Stack đơn giản, dễ đọc, đủ cho API học tập, lại có sẵn Bandit/pip-audit.

**Где хранится секрет JWT?**
🗣 В переменной окружения, в репозиторий он не попадает — там только файл-пример .env.example.
💬 Trong biến môi trường, không commit lên repo — chỉ có file mẫu `.env.example`.

**Что делает middleware require_auth?**
🗣 Это декоратор перед защищёнными методами: берёт токен из заголовка Authorization, проверяет подпись и срок, при ошибке возвращает 401.
💬 Là decorator đặt trước method bảo vệ: lấy token từ header Authorization, kiểm chữ ký + hạn, lỗi thì trả 401.
