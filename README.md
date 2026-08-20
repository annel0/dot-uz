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

## Telegram-safe transport

Новые ссылки используют только алфавит `A-Z a-z 0-9 _ -` после `#` (Base64URL без padding), поэтому Telegram/WhatsApp/Discord/SMS не должны обрывать ссылку на `)`, `*`, `&`, `?` и другой пунктуации старого Base81.

Старые DotURL v0.1 Base81-ссылки по-прежнему декодируются для обратной совместимости.

## Настоящая рекурсивная ссылка (LZ-quine)

Экспериментальный режим `C` — общий URL-safe LZQ-декодер. Это **не** opcode SELF:
декодер знает только три обычные инструкции `L` (literal), `R` (repeat) и `B`
(Base64URL literal). Конкретный payload ниже является настоящим quine: декодирование
выдаёт полный URL, который содержит тот же самый payload.

```text
https://xn--roh.uz/#CBAcaHR0cHM6Ly94bi0tcm9oLnV6LyNDLAiBAcaHR0cHM6Ly94bi0tcm9oLnV6LyNDLAiRAiLADRAiLADLADLAMRAiLADLADLAMRAMLAMRAMLAMRAMLAMRAMLAMRAMLAALAALADRAMLAALAALADRADRAD
```

Проверяемое равенство:

```text
LZQ.decode(fragment.slice(1)) === location.href
```

для канонического `https://xn--roh.uz/`.
