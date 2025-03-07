echo "List of profinity words:\n" >>$2
LC_ALL=C grep -Riwn $1 -a -o -Ff /home/kali/Desktop/Mobilesecurity/profinit-check/profinity-words.txt | cut -b 38-300 >> $2