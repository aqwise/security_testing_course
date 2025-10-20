# Инструкция по добавлению изображений из Confluence

## Для урока XSS (Lesson 2)

````markdown
# XSS Lesson Images

## ✅ Статус: Изображения загружены

Все изображения для урока XSS успешно загружены из Confluence с помощью Playwright MCP (20 октября 2025).

## Для урока XSS (Lesson 2)

### Шаг 1: Скачайте изображения из Confluence

1. Откройте страницу: https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4037378654/Cross-Site+Scripting
2. Войдите в систему
3. Скачайте следующие изображения:

   - `image-20251002-123758.png` → сохраните как `burp-collaborator-diagram.png`
   - `image-20251002-113651.png` → сохраните как `xss-alert-example.png`
   - `photo_2025-10-02_14-43-29-20251002-124329.jpg` → сохраните как `blind-xss-payload.jpg`
   - `image-20251003-055849.png` → сохраните как `blind-xss-result.png`
   - `photo_2025-10-02_13-33-13-20251002-113313.jpg` → сохраните как `svg-xss-example.jpg`

### Шаг 2: Поместите изображения в правильную директорию

Скопируйте скачанные изображения в:
```
public/pics/xss-lesson/
```

### Шаг 3: Изображения автоматически отобразятся

После добавления файлов они автоматически отобразятся в уроке по XSS (Lesson 2).

## Описание изображений:

1. **burp-collaborator-diagram.png** - Диаграмма работы Burp Collaborator для Blind XSS
2. **xss-alert-example.png** - Пример alert окна с сообщением XSS
3. **blind-xss-payload.jpg** - Скриншот отправки Blind XSS payload
4. **blind-xss-result.png** - Результат выполнения Blind XSS атаки
5. **svg-xss-example.jpg** - Пример XSS через SVG файл

## Альтернативный способ (через curl с аутентификацией):

Если у вас есть Confluence API token:

```bash
# Установите переменные окружения
export CONFLUENCE_EMAIL="your-email@example.com"
export CONFLUENCE_API_TOKEN="your-api-token"

# Запустите скрипт
bash download_xss_images.sh
```

Или скачайте вручную через браузер, авторизовавшись в Confluence.
