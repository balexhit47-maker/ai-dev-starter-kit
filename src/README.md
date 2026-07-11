# SecureVault — реализация

Реализация по [ТЗ](../docs/) и [дополнению по архитектуре](../docs/SECURE_VAULT_ARCHITECTURE_ADDENDUM.md). Стек — .NET 8 / C#.

## Структура решения

- **SecureVault.Core** — кроссплатформенное ядро: каскадное шифрование (AES-256-GCM + XChaCha20-Poly1305 через NSec/libsodium), Argon2id + HKDF (`Cryptography/`), формат контейнера с зашифрованным индексом, адаптивным padding и chaffing (`Container/`), модели записей (логин/заметка/файл, `Vault/`), менеджер папки с несколькими сейфами, сервис автоочистки буфера обмена (`Security/`), клиенты синхронизации WebDAV/Яндекс.Диск (`Sync/`). Собирается и тестируется на любой ОС.
- **SecureVault.Core.Tests** — xUnit-тесты (35 тестов): round-trip шифрования, обнаружение подмены/неверного пароля/файла-ключа (в том числе прямая порча байт на диске), переход контейнера через границу bucket-размера, корректное использование сохранённых в заголовке параметров Argon2id при повторном открытии, множественные сейфы, потоковое чтение файла-ключа с лимитом 10 МБ, автоочистка буфера обмена.
- **SecureVault.Windows** — WPF-оболочка (net8.0-windows): экраны списка сейфов, создания/разблокировки, списка и редактирования записей, настроек синхронизации; здесь же — реализация `IPlatformSecurity` через P/Invoke (`VirtualLock`, `SetWindowDisplayAffinity(WDA_MONITOR)`).

## Важное ограничение сборки в этой среде

Разработка велась в Linux-песочнице. `SecureVault.Core` и `SecureVault.Core.Tests` собраны и полностью протестированы здесь (`dotnet test SecureVault.Core.Tests`). **`SecureVault.Windows` (WPF) не может быть собран на Linux** — для этого нужен Windows Desktop SDK, которого в песочнице нет. Код написан и вручную вычитан на соответствие сигнатурам Core-слоя, но не проверялся реальным компилятором WPF. Первым шагом на Windows-машине: открыть `SecureVault.sln` в Visual Studio (или `dotnet build` из-под Windows) и собрать `SecureVault.Windows` — велика вероятность мелких правок на этом этапе.

## Команды

```bash
dotnet build SecureVault.Core/SecureVault.Core.csproj
dotnet test SecureVault.Core.Tests/SecureVault.Core.Tests.csproj

# только на Windows:
dotnet build SecureVault.Windows/SecureVault.Windows.csproj
dotnet run --project SecureVault.Windows
```
