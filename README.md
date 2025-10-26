# WF-Group Countdown-App

Eine elegante und performante Web-Anwendung zum Erstellen, Verwalten und Anzeigen von persönlichen Countdowns zu wichtigen Ereignissen. Geschrieben in Go (Golang) mit einem reinen Vanilla JavaScript Frontend.

![Screenshot der App](https://i.imgur.com/G5gJ0yW.jpeg)

---

## ✨ Features

* **Sichere Benutzerverwaltung:** Registrierung und Login mit Passwort-Hashing (bcrypt).
* **Persistente Sessions:** Benutzer bleiben über Cookies eingeloggt und können sich ausloggen.
* **Dynamisches Frontend:** Countdowns werden in Echtzeit vom Backend geladen und dargestellt.
* **Countdown Management:** Benutzer können ihre eigenen Countdowns erstellen und wieder löschen.
* **Live-Timer:** Jeder Countdown zählt sekundengenau herunter.
* **PWA-fähig:** Die Anwendung kann als App auf dem Homescreen installiert werden und funktioniert dank Service Worker auch offline.
* **Leichtgewichtig & Performant:** Dank Go im Backend und minimalem JavaScript im Frontend extrem schnell.

---

## 🛠️ Tech-Stack

* **Backend:** Go (Golang)
* **Datenbank:** SQLite
* **Frontend:** HTML5, CSS3, Vanilla JavaScript (keine Frameworks)
* **Deployment:** Läuft als `systemd` Service in einem LXC-Container.

---

## 🚀 Setup & Installation (im LXC-Container)

1.  **System vorbereiten und Go installieren:**
    ```bash
    apt update && apt upgrade -y
    apt install golang sqlite3 git -y
    ```

2.  **Repository klonen:**
    ```bash
    git clone [https://github.com/xdnixlos/countdown.git](https://github.com/xdnixlos/countdown.git) /opt/countdown-app
    cd /opt/countdown-app
    ```

3.  **Go-Module herunterladen:**
    ```bash
    go mod tidy
    ```

4.  **Anwendung kompilieren:**
    ```bash
    go build -o countdown-server .
    ```

5.  **Berechtigungen setzen:**
    ```bash
    chown -R root:www-data /opt/countdown-app
    chmod -R 775 /opt/countdown-app
    ```

6.  **`systemd` Service einrichten:**
    * Erstelle die Datei `/etc/systemd/system/countdown.service` mit folgendem Inhalt:
        ```ini
        [Unit]
        Description=Countdown Web Application Service
        After=network.target

        [Service]
        Group=www-data
        WorkingDirectory=/opt/countdown-app
        ExecStart=/opt/countdown-app/countdown-server
        Restart=always

        [Install]
        WantedBy=multi-user.target
        ```

7.  **Service starten und aktivieren:**
    ```bash
    systemctl daemon-reload
    systemctl start countdown.service
    systemctl enable countdown.service
    ```

Die Anwendung läuft jetzt im Hintergrund auf Port `8080`.
