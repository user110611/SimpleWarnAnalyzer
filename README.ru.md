<div align="center">

# 🛡️ SimpleWarnAnalyzer

**Помогает проверить самые уязвимые места компьютера.**

<a href="https://github.com/user110611/SimpleWarnAnalyzer/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/user110611/SimpleWarnAnalyzer?style=for-the-badge&logo=github&labelColor=0d1117&color=f5c542"></a> <a href="https://github.com/user110611/SimpleWarnAnalyzer/forks"><img alt="Forks" src="https://img.shields.io/github/forks/user110611/SimpleWarnAnalyzer?style=for-the-badge&logo=github&labelColor=0d1117&color=58a6ff"></a> <a href="https://github.com/user110611/SimpleWarnAnalyzer/issues"><img alt="Issues" src="https://img.shields.io/github/issues/user110611/SimpleWarnAnalyzer?style=for-the-badge&logo=github&labelColor=0d1117&color=f85149"></a> <a href="https://github.com/user110611/SimpleWarnAnalyzer/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/user110611/SimpleWarnAnalyzer/total?style=for-the-badge&logo=github&labelColor=0d1117&color=3fb950"></a>

<a href="https://github.com/user110611/SimpleWarnAnalyzer/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/user110611/SimpleWarnAnalyzer?style=flat-square&labelColor=0d1117&color=8957e5"></a> <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-0078d4?style=flat-square&labelColor=0d1117&logo=windows"> <img alt="Open source" src="https://img.shields.io/badge/open%20source-100%25-3fb950?style=flat-square&labelColor=0d1117"> <img alt="Languages" src="https://img.shields.io/badge/lang-RU%20%7C%20EN%20%7C%20IT-f0883e?style=flat-square&labelColor=0d1117">

[English](README.md) · **Русский** · [Italiano](README.it.md)

</div>

Сканер Windows в одном файле (без установки, без облака, без телеметрии). За несколько секунд собирает все места, где любят прятаться вирусы, и **простым языком говорит, что с этим делать**.

## Чем он отличается

- **Один экран — один ответ.** На главной написано «Всё в порядке» или «Нужно проверить», показаны 5 самых важных проблем и рекомендуемое действие под каждой. Разбираться не нужно.
- **Объясняет, а не пугает.** У каждой находки есть причины оценки риска 0–100 (нет подписи, запуск из Temp, скрытое окно, подмена Winlogon…). Подписанные файлы Microsoft и ваш белый список не считаются подозрительными.
- **Все места закрепления.** Run / RunOnce (пользователь, система, WOW64, политики), Winlogon, папки автозагрузки, планировщик заданий, Active Setup, IFEO, AppInit_DLLs, службы, процессы, сетевые соединения, файл hosts и глубокий поиск файлов в Temp / AppData / ProgramData / Загрузках.
- **Всё обратимо.** Карантин с возвратом в один клик, журнал всех действий с временем и кнопкой **«Отменить»**, резервная копия `hosts` перед каждой правкой.
- **Защитник Windows (по желанию).** Угрозы и состояние Defender, отметка «прочитано», проверка файла, управление исключениями и защищёнными папками.
- **Редактор файла hosts.** Добавление, изменение и удаление записей с автоматической резервной копией.
- **Что изменилось с прошлого раза.** Новые и пропавшие элементы автозагрузки, метки «впервые замечено».
- **Приватность.** Маленький веб-интерфейс только на `127.0.0.1` с токеном на каждый запуск. Ничего не покидает ваш ПК.
- **Три языка.** Русский, английский и итальянский — переключатель в шапке (язык определяется автоматически).

> Это эвристический помощник, а не замена полноценному антивирусу. «Подозрительно» значит «стоит посмотреть», а не приговор.

## Запуск

Скачайте `SySscaner.exe` на странице [Releases](../../releases) и запустите — в браузере откроется `http://127.0.0.1:8787`. Для полного доступа запускайте от администратора.

```
SySscaner.exe                 # веб-интерфейс
SySscaner.exe --console       # старое консольное меню
SySscaner.exe --no-open --port 8787
```

Ваши данные (архив, журнал, белый список, настройки) хранятся в папке `Данные` рядом с exe.

## Сборка

Нужен g++ (MSYS2 / MinGW-w64):

```
build.bat                     # или: powershell -File build.ps1 [-Out имя.exe]
```

`ui.html` встраивается в exe при сборке. Если рядом с exe лежит `ui.html`, при запуске используется он — удобно для правки интерфейса без пересборки.

## Лицензия

См. [LICENSE](LICENSE).
