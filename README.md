# Host-Intusion-Detection-System
Detect and display incoming threats by using attack signatures for a variety of threats such as:
-Brute force ssh attacks
-SQL injection
-Cross-Site scripting
-Directory traversal 
-Local file inclusion
-Denial of service attacks

This project was designed to run on WSL2 with an apache server running on that instance. While the server is running, the program will detect attacks targeting the server through the WSL2 instance. The program will then update a table with characteristics of the attack such as date/time of attack, attack type, the suspected attack input, and severity level.
