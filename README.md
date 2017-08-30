# Chat
A simple desktop chat application. A work in progress.

I've used this project to learn more about socket programming and threading. It sends text messages across local networks in a GUI using a direct connection, no server in between. Besides some quality of life features, the next major features are to add asymmetric and symmetric encryption, include Hash-based Message Authentication Code (HMAC), and getting messages across the internet instead of just local networks.

For two users to chat, the users start up their own applications. One user sets their application to "Listen" mode and begins to listen on a desired port. The other user goes to "Connect" mode, then connects to the first user at their IP address and on the previously chosen port. The two users would need to agree on what port to connect on, and the connecting user would need to  know the IP address of the listening user beforehand.

The chat application works best on Mac OS. There seem to be some problems on Windows and certain versions of Linux where messages are dropped, and on Linux the application freezes when the keepalive signal is lost, rather than just closing the connection.
