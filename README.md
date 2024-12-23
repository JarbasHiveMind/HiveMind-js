# HiveMind JS

![logo](./hivemindjs.png)

HiveMind JS is a JavaScript client for interacting with the HiveMind system, a distributed voice assistant platform. This client enables communication with HiveMind services via WebSocket, supporting encryption, message handling, and simple interactions.

## Features

- **WebSocket Communication**: Connects to HiveMind services over WebSocket for real-time communication.
- **Encryption Support**: Encrypts and decrypts messages to ensure secure communication.
- **Handshake Protocol**: Handles the authentication and encryption handshake process.
- **Message Handling**: Processes various types of hivemind protocol messages, including "hello", "bus", and "handshake".
- **Simple Interactions**: Send and receive messages, including speech-related messages like "speak" and custom utterances.

## Prerequisites

- A running HiveMind server.
- Web browser that supports modern JavaScript features like WebSockets and WebCrypto API.

## Installation

You can directly include the client in your HTML file from the provided CDN links.

```html
<script src="https://jarbashivemind.github.io/HiveMind-js/static/js/smcrypto.js"></script>
<script src="https://jarbashivemind.github.io/HiveMind-js/static/js/webcrypto-shim.js"></script>
<script src="https://jarbashivemind.github.io/HiveMind-js/static/js/hivemind.js"></script>
```

Alternatively, clone the repository and host the files locally.

## Usage Example

Here’s a simple example to demonstrate how to use the HiveMind JS client in a web application.

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
        // HiveMind socket connection details
        const useragent = "HivemindWebChat";    // User-agent identifier
        const ip = "127.0.0.1";                 // HiveMind server IP address
        const port = 5678;                      // HiveMind server port
        const key = "iagsdhhASFasgsf1N";        // Access key for authentication
        const password = "ivf1NQSkQNogWYyr";    // Password for encryption

        // Create a new HiveMind connection instance
        const hivemind_connection = new JarbasHiveMind()

        // Handle successful connection
        hivemind_connection.onHiveConnected = function () {
            this.start_handshake()
            window.alert("Welcome to the HiveMind Webchat client!")
        };

        // Handle received "speak" messages
        hivemind_connection.onMycroftSpeak = function (mycroft_message) {
            let utterance = mycroft_message.data.utterance;
            window.alert(utterance);  // Display the message
        }

        // Handle disconnection event
        hivemind_connection.onHiveDisconnected = function () {
            window.alert("HiveMind connection lost...")
        };

        // Connect to the HiveMind server
        hivemind_connection.connect(ip, port, useragent, key, password);

        // Send a test utterance after 5 seconds
        setTimeout(() => hivemind_connection.sendUtterance("tell me a joke"), 5000)

    </script>

</body>

</html>
```

### How it works

1. **Connecting to HiveMind**: 
   - Create an instance of `JarbasHiveMind` and use the `connect()` method to establish a WebSocket connection with the HiveMind server.
   - Provide the server's IP address, port, username, access key, and password for authentication.

2. **Handling Events**:
   - `onHiveConnected`: This event is triggered once the WebSocket connection is established. You can use this event to display a welcome message or initialize your application.
   - `onMycroftSpeak`: This event is triggered when HiveMind sends a "speak" message. The `mycroft_message` contains the data to be spoken, which can be displayed in your app.
   - `onHiveDisconnected`: This event is triggered when the connection is lost, allowing you to handle disconnections gracefully.

3. **Sending Messages**:
   - The `sendUtterance()` method allows you to send messages or requests to the HiveMind server. In this example, it sends a request to "tell me a joke" after a short delay.

## API Methods

### `connect(host, port, username, accessKey, password)`
Establishes a WebSocket connection to the HiveMind server.

- **Parameters**:
  - `host`: The IP address or hostname of the HiveMind server.
  - `port`: The port number on which the HiveMind server is listening.
  - `username`: Username for authentication.
  - `accessKey`: Access key for authentication.
  - `password`: Password for secure encryption.

### `sendMessage(message)`
Sends an encrypted message to the HiveMind server.

- **Parameters**:
  - `message`: The message object to be sent. If an encryption key is set, the message will be encrypted before being sent.

### `sendUtterance(utterance)`
Sends a specific utterance to the HiveMind server.

- **Parameters**:
  - `utterance`: A string message to be sent to HiveMind.

### `onHiveConnected`
Callback function triggered when the connection to HiveMind is established.

### `onHiveDisconnected`
Callback function triggered when the connection to HiveMind is lost.

### `onMycroftSpeak`
Callback function triggered when HiveMind sends a "speak" message.

## Troubleshooting

- **Connection Issues**: Ensure the HiveMind server is running and accessible at the provided IP address and port.
- **Encryption Errors**: Check that the correct password and encryption keys are being used.

## Contributing

Feel free to fork this repository and submit pull requests. Contributions are welcome!

## License

This project is licensed under the Apache License.
