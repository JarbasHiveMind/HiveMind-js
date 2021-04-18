# HiveMind JS

![logo](./hivemindjs.png)

javascript client for HiveMind

## Usage

```html
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <title>HiveMindJs Demo</title>
    <script src="https://jarbashivemind.github.io/HiveMind-js/static/js/smcrypto.js"></script>
    <script src="https://jarbashivemind.github.io/HiveMind-js/static/js/webcrypto-shim.js"></script>
    <script src="https://jarbashivemind.github.io/HiveMind-js/static/js/hivemind.js"></script>
</head>

<body>
    <script type="text/javascript">
        // HiveMind socket
        const user = "HivemindWebChat";
        const key = "ivf1NQSkQNogWYyr";
        const ip = "127.0.0.1";
        const port = 5678;
        const crypto_key = "ivf1NQSkQNogWYyr";
        
        const hivemind_connection = new JarbasHiveMind()

        hivemind_connection.onHiveConnected = function () {
            window.alert("Welcome to the HiveMind Webchat client!")
        };

        hivemind_connection.onMycroftSpeak = function (mycroft_message) {
            let utterance = mycroft_message.data.utterance;
            window.alert(utterance)
        }

        hivemind_connection.onHiveDisconnected = function () {
            window.alert("Hivemind connection lost...")
        };

        hivemind_connection.connect(ip, port, user, key, crypto_key);

        setTimeout(() => hivemind_connection.sendUtterance("tell me a joke"), 5000)

    </script>

</body>

</html>
```