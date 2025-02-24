import os
import subprocess
import threading
import time
from flask import Flask, render_template_string

# Chemin vers le fichier de configuration SSH
CONFIG_FILE = r"C:\Users\thoger\.ssh\config"

# Liste de serveurs extraits : chaque entrée sera un dict avec "name" et "hostName"
servers = []

# Dictionnaire global pour l'état de chaque serveur : True = up, False = down
server_status = {}

def load_config(file_path):
    """Lit et parse le fichier de config pour extraire les entrées SSH."""
    global servers
    servers = []
    if not os.path.exists(file_path):
        print(f"Fichier non trouvé : {file_path}")
        return
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    current_server = None
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Détection d'une nouvelle entrée Host
        if line.lower().startswith("host "):
            if current_server:
                servers.append(current_server)
            parts = line.split()
            if len(parts) >= 2:
                current_server = {"name": parts[1], "hostName": None}
        elif current_server and line.lower().startswith("hostname "):
            parts = line.split()
            if len(parts) >= 2:
                current_server["hostName"] = parts[1]
    if current_server:
        servers.append(current_server)

def ping_server(host):
    """
        Effectue 3 pings via la commande Windows.
        Retourne True si au moins une tentative réussit, sinon False.
        Chaque ping envoie 1 paquet (-n 1) avec un timeout de 1000 ms (-w 1000).
    """
    try:
        result = subprocess.run(["ping", "-n", "1", "-w", "1000", host],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        if result.returncode == 0:
            return True
    except Exception as e:
        print(f"Erreur lors du ping de {host}: {e}")
    return False

def update_statuses():
    """Fonction qui met à jour en continu l'état de chaque serveur toutes les secondes."""
    while True:
        for srv in servers:
            host = srv.get("hostName")
            if host:
                status = ping_server(host)
                server_status[srv["name"]] = status
        time.sleep(1)

# Démarrer le thread de mise à jour des statuts
status_thread = threading.Thread(target=update_statuses, daemon=True)
status_thread.start()

# Initialisation de Flask
app = Flask(__name__)

# Modèle HTML pour afficher la page de monitoring
html_template = """
        <!DOCTYPE html>
        <html lang="fr">
        <head>
        <meta charset="UTF-8">
        <title>État des serveurs SSH</title>
        <!-- Auto-refresh toutes les 2 secondes -->
        <meta http-equiv="refresh" content="2">
        <style>
            body { font-family: Arial, sans-serif; }
            .server { margin: 10px 0; }
            .led {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
            background-color: gray;
            }
            .up { background-color: green; }
            .down { background-color: red; }
        </style>
        </head>
        <body>
        <h1>Monitoring des serveurs SSH</h1>
        {% for srv in servers %}
            <div class="server">
            <span class="led {% if statuses[srv.name] %}up{% else %}down{% endif %}"></span>
            <strong>{{ srv.name }}</strong> ({{ srv.hostName }}) : 
            {% if statuses[srv.name] %}
                UP
            {% else %}
                DOWN
            {% endif %}
            </div>
        {% endfor %}
        </body>
        </html>
"""

@app.route("/")
def index():
    return render_template_string(html_template, servers=servers, statuses=server_status)

if __name__ == "__main__":
    # Charger la configuration au démarrage
    load_config(CONFIG_FILE)
    # Initialiser les statuts à False par défaut
    for srv in servers:
        server_status[srv["name"]] = False
    # Démarrer le serveur Flask accessible sur toutes les interfaces, port 5000
    app.run(host="127.0.0.1", port=5000)
