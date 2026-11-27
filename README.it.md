# SimpleWarnAnalyzer

[![Stars](https://img.shields.io/github/stars/user110611/SimpleWarnAnalyzer?style=flat-square)](https://github.com/user110611/SimpleWarnAnalyzer/stargazers) [![Forks](https://img.shields.io/github/forks/user110611/SimpleWarnAnalyzer?style=flat-square)](https://github.com/user110611/SimpleWarnAnalyzer/forks) [![Issues](https://img.shields.io/github/issues/user110611/SimpleWarnAnalyzer?style=flat-square)](https://github.com/user110611/SimpleWarnAnalyzer/issues) [![Downloads](https://img.shields.io/github/downloads/user110611/SimpleWarnAnalyzer/total?style=flat-square)](https://github.com/user110611/SimpleWarnAnalyzer/releases)

[English](README.md) · [Русский](README.ru.md) · **Italiano**

Aiuta ad analizzare le aree più vulnerabili del computer.

Uno scanner per Windows in un solo file (senza installazione, senza cloud, senza telemetria). In pochi secondi raccoglie tutti i punti in cui i malware amano nascondersi e ti dice **in parole semplici cosa fare**.

## Perché è diverso

- **Una schermata, una risposta.** La Home dice «Tutto a posto» oppure «Da controllare», elenca i 5 problemi più importanti e mette l'azione consigliata sotto ciascuno. Non servono competenze tecniche.
- **Spiega, non spaventa.** Ogni risultato ha i motivi del suo punteggio di rischio 0–100 (file senza firma, avvio da Temp, finestra nascosta, Winlogon manomesso…). I file Microsoft firmati e la tua lista bianca non vengono segnalati.
- **Tutti i punti di persistenza.** Run / RunOnce (utente, sistema, WOW64, criteri), Winlogon, cartelle di esecuzione automatica, Utilità di pianificazione, Active Setup, IFEO, AppInit_DLLs, servizi, processi, connessioni di rete, file hosts e ricerca approfondita in Temp / AppData / ProgramData / Download.
- **Tutto reversibile.** Quarantena con ripristino in un clic, registro di ogni azione con data e ora e pulsante **Annulla**, copia di sicurezza di `hosts` prima di ogni modifica.
- **Windows Defender integrato (facoltativo).** Minacce e stato di Defender, segno «letto», scansione di un file, gestione di esclusioni e cartelle protette.
- **File hosts modificabile.** Aggiungi, modifica o elimina voci con backup automatico.
- **Cosa è cambiato dall'ultima volta.** Elementi di avvio nuovi e scomparsi, indicazione «visto per la prima volta».
- **Privato per progettazione.** Una piccola interfaccia web solo su `127.0.0.1`, protetta da un token per ogni avvio. Nulla lascia il tuo PC.
- **Tre lingue.** Russo, inglese e italiano, selezionabili nell'intestazione (rilevamento automatico).

> È un assistente euristico, non un sostituto di un antivirus completo. «Sospetto» significa «vale la pena guardare», non è una condanna.

## Avvio

Scarica `SySscaner.exe` dalla pagina [Releases](../../releases) e avvialo — il browser aprirà `http://127.0.0.1:8787`. Per l'accesso completo avvialo come amministratore.

```
SySscaner.exe                 # interfaccia web
SySscaner.exe --console       # vecchio menu da console
SySscaner.exe --no-open --port 8787
```

I tuoi dati (archivio, registro, lista bianca, impostazioni) si trovano nella cartella `Данные` accanto all'exe.

## Compilazione

Serve g++ (MSYS2 / MinGW-w64):

```
build.bat                     # oppure: powershell -File build.ps1 [-Out nome.exe]
```

`ui.html` viene incorporato nell'exe durante la compilazione. Se accanto all'exe c'è `ui.html`, viene usato quello — comodo per modificare l'interfaccia senza ricompilare.

## Licenza

Vedi [LICENSE](LICENSE).
