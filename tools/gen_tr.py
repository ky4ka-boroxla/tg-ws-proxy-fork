import json, re

STRINGS = {
    "window.title": ("Settings", "Настройки"),
    "nav.connection": ("Connection", "Подключение"),
    "nav.routing": ("Routing", "Маршруты"),
    "nav.cloudflare": ("Cloudflare", "Cloudflare"),
    "nav.advanced": ("Advanced", "Дополнительно"),
    "nav.interface": ("Application", "Приложение"),
    "connection.title": ("Connection", "Подключение"),
    "connection.subtitle": ("Add this proxy to Telegram or scan the QR code with your phone.", "Добавьте прокси в Telegram или отсканируйте QR-код телефоном."),
    "open.tg": ("Add to Telegram", "Добавить в Telegram"),
    "copy.link": ("Copy link", "Скопировать ссылку"),
    "copied": ("Copied", "Скопировано"),
    "scan": ("Scan with your phone", "Наведите камеру телефона"),
    "link.unavailable": ("Fix the highlighted fields to get a link", "Исправьте подсвеченные поля, чтобы получить ссылку"),
    "address.title": ("Local address", "Локальный адрес"),
    "address.host": ("Listen address", "Адрес прослушивания"),
    "address.host.hint": ("Usually 127.0.0.1. Use 0.0.0.0 to share the proxy on your network.", "Обычно 127.0.0.1. Укажите 0.0.0.0, чтобы открыть прокси для локальной сети."),
    "address.port": ("Port", "Порт"),
    "address.port.hint": ("1–65535, default 1443", "1–65535, по умолчанию 1443"),
    "secret": ("Secret", "Секрет"),
    "secret.hint": ("32 hex characters. Changing it invalidates the old link.", "32 hex-символа. После смены старая ссылка перестанет работать."),
    "show": ("Show", "Показать"),
    "hide": ("Hide", "Скрыть"),
    "generate": ("Generate new", "Сгенерировать"),
    "routing.title": ("Routing", "Маршруты"),
    "routing.subtitle": ("How traffic reaches Telegram datacenters.", "Как трафик попадает в дата-центры Telegram."),
    "dc.title": ("Datacenters", "Дата-центры"),
    "dc.hint": ("One DC:IP per line, for example 2:149.154.167.220. Direct WebSocket connections go through these addresses.", "По одной записи DC:IP в строке, например 2:149.154.167.220. Прямые WebSocket-соединения идут через эти адреса."),
    "direct.title": ("Direct connections", "Прямые соединения"),
    "pool": ("Pool size per DC", "Размер пула на DC"),
    "pool.hint": ("Connections kept ready. 0 disables direct WebSocket.", "Заранее открытых соединений. 0 отключает прямой WebSocket."),
    "buf": ("Socket buffer, KB", "Буфер сокета, КБ"),
    "buf.hint": ("Send and receive buffer. Default 256.", "Буфер отправки и приёма. По умолчанию 256."),
    "cloudflare.title": ("Cloudflare", "Cloudflare"),
    "cloudflare.subtitle": ("Fallback routes when direct access is blocked.", "Обходные маршруты, если прямой доступ заблокирован."),
    "cf.title": ("CF proxy", "CF-прокси"),
    "cf.enable": ("Use CF proxy", "Использовать CF-прокси"),
    "cf.enable.desc": ("Falls back to Cloudflare-proxied domains when direct WebSocket fails.", "Резервный маршрут через домены за Cloudflare, если прямой WebSocket недоступен."),
    "h2": ("HTTP/2 for media", "HTTP/2 для медиа"),
    "h2.desc": ("Multiplexes media downloads over one connection. Requires CF proxy and TLS.", "Мультиплексирует загрузку медиа в одном соединении. Нужны CF-прокси и TLS."),
    "custom": ("Own domains", "Свои домены"),
    "custom.desc": ("Use your Cloudflare domains instead of the automatic list.", "Свои домены на Cloudflare вместо автоматического списка."),
    "domains.placeholder": ("example.com, another.com", "example.com, another.com"),
    "worker.title": ("CF worker", "CF-воркер"),
    "worker.enable": ("Use CF worker", "Использовать CF-воркер"),
    "worker.desc": ("Routes traffic through your Cloudflare Worker domains.", "Маршрут через ваши домены Cloudflare Worker."),
    "test": ("Test", "Проверить"),
    "testing": ("Testing…", "Проверяем…"),
    "guide": ("Guide", "Инструкция"),
    "report.all": ("all {total} servers reachable", "доступны все {total} серверов"),
    "report.partial": ("working {ok_list}; unreachable {fail_list}", "работают {ok_list}; недоступны {fail_list}"),
    "report.none": ("unavailable", "недоступен"),
    "advanced.title": ("Advanced", "Дополнительно"),
    "advanced.subtitle": ("Logging and low-level switches.", "Журнал и низкоуровневые параметры."),
    "verbose": ("Verbose log", "Подробный журнал"),
    "verbose.desc": ("Writes debug details to the log file.", "Пишет отладочные сообщения в файл журнала."),
    "no.secure": ("Plain connections to Cloudflare", "Без TLS к Cloudflare"),
    "no.secure.desc": ("Uses port 80 for CF proxy and worker. Disables HTTP/2.", "Порт 80 для CF-прокси и воркера. Отключает HTTP/2."),
    "log.mb": ("Log size limit, MB", "Лимит журнала, МБ"),
    "log.mb.hint": ("Older entries rotate out.", "Старые записи ротируются."),
    "open.log": ("Open log", "Открыть журнал"),
    "open.folder": ("Open data folder", "Открыть папку данных"),
    "files.title": ("Files", "Файлы"),
    "interface.title": ("Application", "Приложение"),
    "interface.subtitle": ("Look, language and startup.", "Внешний вид, язык и автозапуск."),
    "language": ("Language", "Язык"),
    "theme": ("Theme", "Тема"),
    "theme.auto": ("System", "Системная"),
    "theme.light": ("Light", "Светлая"),
    "theme.dark": ("Dark", "Тёмная"),
    "autostart": ("Start with Windows", "Запускать вместе с Windows"),
    "autostart.desc": ("Launches to the tray when you sign in.", "Запускается в трее при входе в систему."),
    "accent": ("Accent color", "Акцентный цвет"),
    "accent.desc": ("Colors buttons, highlights and gradients.", "Окрашивает кнопки, акценты и градиенты."),
    "hero.label": ("Your Telegram proxy", "Ваш прокси для Telegram"),
    "mode": ("Appearance", "Оформление"),
    "about": ("About", "О программе"),
    "version": ("Version", "Версия"),
    "check.updates": ("Check for updates", "Проверить обновления"),
    "checking": ("Checking…", "Проверяем…"),
    "up.to.date": ("You have the latest version.", "Установлена последняя версия."),
    "update.available": ("Version {version} is available.", "Доступна версия {version}."),
    "update.failed": ("Could not check for updates.", "Не удалось проверить обновления."),
    "update.ahead": ("This build is newer than the latest release.", "Эта сборка новее последнего релиза."),
    "open.release": ("Open release page", "Страница релиза"),
    "unsaved": ("Unsaved changes", "Есть несохранённые изменения"),
    "saved": ("No changes", "Изменений нет"),
    "reset": ("Reset", "Сбросить"),
    "cancel": ("Cancel", "Отмена"),
    "save": ("Save", "Сохранить"),
    "restart.title": ("Restart the proxy?", "Перезапустить прокси?"),
    "restart.body": ("Some changes take effect only after the proxy restarts.", "Часть изменений применится только после перезапуска прокси."),
    "restart.now": ("Restart now", "Перезапустить"),
    "restart.later": ("Later", "Позже"),
    "error.title": ("Could not save", "Не удалось сохранить"),
    "dismiss": ("Dismiss", "Закрыть"),
    "fr.title": ("Welcome to TG WS Proxy", "Добро пожаловать в TG WS Proxy"),
    "fr.subtitle": ("The proxy is already running in the tray. Add it to Telegram in one click.", "Прокси уже работает в трее. Добавьте его в Telegram одним нажатием."),
    "fr.add": ("Add to Telegram", "Добавить в Telegram"),
    "fr.manual.title": ("Or add it manually", "Или добавьте вручную"),
    "fr.manual.hint": ("Telegram → Settings → Advanced → Connection type → Use custom proxy → MTProto.", "Telegram → Настройки → Продвинутые → Тип соединения → Использовать собственный прокси → MTProto."),
    "fr.tray": ("Settings and the log are in the tray icon menu.", "Настройки и журнал находятся в меню значка в трее."),
    "fr.start": ("Get started", "Начать"),
}

for idx, lang in enumerate(("en", "ru")):
    path = f"i18n/{lang}.json"
    data = json.load(open(path, encoding="utf-8"))
    for key, pair in STRINGS.items():
        data["ui." + key] = pair[idx]
    json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    open(path, "a").write("\n")

def prop(key):
    return key.replace(".", "-")

def setter(key):
    return "set_" + key.replace(".", "_")

with open("ui/tr.slint", "w", encoding="utf-8") as f:
    f.write("export global Tr {\n")
    for key in STRINGS:
        f.write(f"    in property <string> {prop(key)};\n")
    f.write("}\n")

with open("src/win/tr_gen.rs", "w", encoding="utf-8") as f:
    f.write("use crate::i18n::t;\nuse crate::win::ui::Tr;\nuse slint::ComponentHandle;\n\n")
    f.write("pub fn apply<C: ComponentHandle>(component: &C)\nwhere\n    for<'a> Tr<'a>: slint::Global<'a, C>,\n{\n")
    f.write("    let tr = component.global::<Tr>();\n")
    for key in STRINGS:
        f.write(f"    tr.{setter(key)}(t(\"ui.{key}\").into());\n")
    f.write("}\n")
print(len(STRINGS))
