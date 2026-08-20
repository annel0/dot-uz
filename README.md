# ⏺.uz — DotURL v2 MAX

Готовая статическая версия сокращателя для GitHub Pages.

## Что изменилось в v2

DotURL v2 выбирает минимальный payload среди старых и новых кодеков. Новая ветка использует:

- обученный URL-словарь (core + extended tokens);
- глобальный shortest-path парсер вместо greedy-разбора;
- LZ backreferences для повторов внутри одного URL;
- binary packing для UUID, hex, decimal, percent-encoding и Base64;
- 5-bit / 6-bit packing для URL-подобных литералов;
- corpus-trained canonical Huffman;
- rANS для очень больших URL;
- DEFLATE и preset dictionaries как дополнительные кандидаты;
- Telegram-safe Base64URL transport: только `A-Z a-z 0-9 _ -` после `#`.

Старые DotURL v1/v2-safe ссылки и экспериментальный LZQ-quine продолжают декодироваться.

## Деплой

1. Распаковать содержимое архива в корень публичного GitHub-репозитория.
2. Settings → Pages → Deploy from a branch → `main` / `/ (root)`.
3. Custom domain: `xn--roh.uz`.
4. DNS корня домена направить на GitHub Pages.
5. После проверки DNS включить Enforce HTTPS.

`CNAME` и `.nojekyll` уже находятся в архиве.

## Файлы

- `index.html` — интерфейс круга `.uz`;
- `app.js` — UI, копирование и генерация ссылки;
- `doturl-core.mjs` — DotURL v2 MAX;
- `doturl-browser.js` — браузерный backend и redirect;
- `CNAME` — `xn--roh.uz`.

## Важно

Это lossless self-contained shortener: исходный URL хранится внутри fragment, базы данных нет. Поэтому криптографически случайный payload (подпись, токен, ciphertext) невозможно существенно сжать без внешнего хранилища.
