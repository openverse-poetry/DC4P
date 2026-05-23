# NanoCell - Ultra-Compact Cellular Network

Минималистичная сотовая сеть с поддержкой белых/серых IP, администрированием и P2P архитектурой.

## Структура проекта

```
nanocell/
├── core/                   # Ядро системы
│   ├── __init__.py
│   ├── network.py          # Сетевой движок (NAT traversal, UDP hole punching)
│   ├── crypto.py           # Шифрование (NaCl/libsodium)
│   ├── protocol.py         # Бинарный протокол связи
│   └── storage.py          # LSM-tree база данных
│
├── server/                 # Серверная часть
│   ├── __init__.py
│   ├── bootstrap.py        # Bootstrap сервер (координация)
│   ├── relay.py            # Relay сервер (для серых IP)
│   └── auth.py             # Авторизация и роли
│
├── client/                 # Клиентская часть
│   ├── __init__.py
│   ├── app.py              # Основное приложение
│   ├── ui.py               # TUI интерфейс (textual)
│   └── p2p.py              # P2P соединения
│
├── admin/                  # Админ панель
│   ├── __init__.py
│   ├── cli.py              # CLI для владельца
│   └── roles.py            # Управление ролями
│
├── tests/                  # Тесты
│   ├── test_network.py
│   ├── test_crypto.py
│   └── test_protocol.py
│
├── config/                 # Конфигурация
│   ├── default.yaml
│   └── production.yaml
│
├── requirements.txt
├── setup.py
├── run_server.py
├── run_client.py
├── run_admin.py
└── README.md
```

## Архитектурные принципы

### 1. Гибридная P2P + Client-Server архитектура
- **Белые IP**: Прямое P2P соединение через UDP hole punching
- **Серые IP**: Relay сервер как fallback
- **Bootstrap сервер**: Только для координации (не хранит сообщения)

### 2. Эффективность
- Бинарный протокол (Protocol Buffers / MessagePack)
- UDP вместо TCP для снижения overhead
- End-to-end шифрование
- LSM-tree для хранения (быстрая запись, компактное хранение)

### 3. Безопасность
- NaCl cryptography (curve25519, chacha20, poly1305)
- Identity-based encryption
- Role-based access control (RBAC)

### 4. Масштабируемость
- Stateless bootstrap сервера
- Горизонтальное масштабирование relay серверов
- DHT для discovery (опционально)

## Ключевые компоненты

### Сетевой движок (network.py)
```python
# NAT traversal стратегии:
# 1. UDP Hole Punching (для белых IP)
# 2. TURN-like relay (для серых IP)
# 3. ICE (Interactive Connectivity Establishment)
```

### Протокол (protocol.py)
```
Message Format:
[2 bytes] - Magic number
[1 byte]  - Message type
[2 bytes] - Payload length
[N bytes] - Encrypted payload
[16 bytes] - MAC (authentication tag)
```

### База данных (storage.py)
```python
# LSM-tree реализация:
# - MemTable (in-memory skip list)
# - SSTables (immutable files on disk)
# - Compaction (фоновое слияние)
# ~1000 строк кода для полной реализации
```

## План реализации (~5000 строк)

| Компонент | Строки | Описание |
|-----------|--------|----------|
| Crypto    | 400    | Шифрование, ключи, подписи |
| Protocol  | 300    | Бинарный протокол, сериализация |
| Storage   | 1000   | LSM-tree база данных |
| Network   | 800    | UDP, hole punching, relay |
| Server    | 600    | Bootstrap + Relay сервера |
| Client    | 700    | P2P клиент, UI |
| Admin     | 400    | RBAC, CLI для владельца |
| Tests     | 800    | Unit + integration тесты |
| Config/Utils | 500 | Конфиги, утилиты, логирование |
| **Итого** | **5500** | Целевой объем |

## Запуск

```bash
# Bootstrap сервер
python run_server.py --role bootstrap --port 9000

# Relay сервер
python run_server.py --role relay --port 9001

# Клиент
python run_client.py --identity my_id

# Админ панель
python run_admin.py --owner-key <private_key>
```

## Конкурентные преимущества перед Telegram

1. **Полный контроль**: Вы владеете всей инфраструктурой
2. **Приватность**: E2E шифрование по умолчанию, no metadata storage
3. **Эффективность**: Бинарный протокол + UDP = меньше трафика
4. **Гибкость**: Работает с белыми и серыми IP
5. **Компактность**: ~5000 строк vs миллионы у Telegram
6. **Администрирование**: Гранулярный контроль над сетью

## Roadmap

- [x] Проектирование архитектуры
- [ ] Реализация ядра (crypto, protocol, storage)
- [ ] Сетевой движок (NAT traversal)
- [ ] Сервера (bootstrap, relay)
- [ ] Клиент с TUI интерфейсом
- [ ] Админ панель для владельца
- [ ] Тесты и документация
