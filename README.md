# ⏺.uz

Минималистичная главная + client-side DotURL v0.1.

## Что делает

- Обычное открытие `https://⏺.uz/` показывает только круг и `.uz`.
- Клик по кругу → `сократить ссылку`.
- Ссылка кодируется полностью на клиенте, без БД и API.
- Получается `https://⏺.uz/#<DotURL>`.
- При открытии такого URL браузер декодирует fragment и делает `location.replace()`.
- Автоматический redirect разрешён только на `http:` и `https:`.

## GitHub Pages

Архив уже содержит:

- `CNAME` → `xn--roh.uz`
- `.nojekyll`
- `index.html`
- `app.js`
- DotURL codec

Можно распаковать содержимое прямо в корень публичного репозитория, затем:

1. `Settings → Pages`
2. `Deploy from a branch`
3. `main / (root)`
4. Custom domain: `xn--roh.uz`
5. После проверки DNS включить `Enforce HTTPS`.

## DNS для apex-домена

```text
@  A  185.199.108.153
@  A  185.199.109.153
@  A  185.199.110.153
@  A  185.199.111.153
```

## Зависимость

`doturl-browser.js` импортирует `pako@3.0.1` с jsDelivr. Сам сайт и codec статические; серверная часть не требуется.

## Важно

Wire-format DotURL v0.1 экспериментальный. Не меняй `doturl-core.mjs`, если уже раздал ссылки: старые fragment должны оставаться декодируемыми.
