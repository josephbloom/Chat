# Chat
A simple desktop chat application. A work in progress.

I've used this project to learn more about socket programming and threading. Besides some quality of life features, the next major features are to add asymmetric and symmetric encryption, include Hash-based Message Authentication Code (HMAC), and getting messages across the internet, instead of just local networks.

For two users to chat, the users start up their own applications, one user sets their application to "Listen" mode and begins to listen on a desired port, and the other user goes to "Connect" mode then connects to the first user at their IP address and on the chosen port.

The chat application works best on Mac OS. There seem to be some problems on Windows and certain versions of Linux where messages are dropped, and on Linux, the application freezes when the keepalive signal is lost, rather than just closing the connection.
