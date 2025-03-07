echo "List of opcodes:\n" >> $2
LC_ALL=C grep -Rw $1 -a -o -f /home/kali/Desktop/Mobilesecurity/opcode-check/opcodes.txt | cut -b 38-300 >> $2