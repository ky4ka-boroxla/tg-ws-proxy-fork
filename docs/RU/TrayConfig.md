# Файлы конфигурации Tray-приложения

Tray-приложение хранит данные в `%APPDATA%/TgWsProxy`.

```json
{
  "host": "127.0.0.1",
  "port": 1443,
  "secret": "...",
  "dc_ip": [
    "2:149.154.167.220",
    "4:149.154.167.220"
  ],
  "verbose": false,
  "buf_kb": 256,
  "pool_size": 4,
  "log_max_mb": 5,
  "cfproxy": true,
  "h2": true,
  "cfproxy_user_domain_enabled": false,
  "cfproxy_user_domain": [],
  "cfproxy_worker_enabled": false,
  "cfproxy_worker_domain": [],
  "force_test_dc": false,
  "no_secure": false,
  "appearance": "auto",
  "language": "ru"
}
```

Ключ `autostart` включает автозапуск при входе в систему.
