=Example attack logs 
==Brute force ssh attack is WSL2: (WORKS[5 attemps within 60sec]) 
    for i in {1..6}; do
  echo "Jul 30 14:00:0$i sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2" | sudo tee -a /var/log/auth.log
done

==SQL injection in web logs: (WORKS)
echo '192.168.1.200 - - "GET /product.php?item=5%20UNION%20SELECT%20null,null-- HTTP/1.1" 200 1982' | sudo tee -a /var/log/apache2/access.log

==XXS (WORKS)
echo '127.0.0.1 - - "GET /?q=<script>alert(`XSS`)</script> HTTP/1.1" 200 1234' | sudo tee -a /var/log/apache2/access.log

==Directory Traversal (WORKS)
curl "http://localhost/index.php?page=../../../../etc/passwd"

==LFI (WORKS)
echo '127.0.0.1 - -  "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 200 1234 "-" "Mozilla/5.0"' | sudo tee -a /var/log/apache2/access.log
 
==DOS Patterns (WORKS['{1..xtimes}', temporarily 5 attemps in 5 sec])
for i in {1..6}; do curl http://localhost/ > /dev/null; done

=Download flask

=Directory project is in:
cd /mnt/c/Users/BrianB/OneDrive/Desktop/log_parser_project 

=Start Apache server
sudo service apache2 start

=Run this after every attack:
python3 main.py

=Apache website
http://localhost/alerts.html


This attack line: XSS,"Possible Xss attack: ::1 - - [05/Aug/2025:13:43:41 -0400] ""GET /?q=<script>alert('XSS')</script> HTTP",2025-08-05 13:48:37,Medium,access.log,"::1 - - [05/Aug/2025:13:43:41 -0400] ""GET /?q=<script>alert('XSS')</script> HTTP/1.1"" 200 10926 ""-"" ""curl/8.5.0""" . It was actually printed "XSS" in my dashboard page as a pop up, an acutal vunerabilty. I was directly inserting incident['summary'] (and potentially source) into the HTML output without escaping.