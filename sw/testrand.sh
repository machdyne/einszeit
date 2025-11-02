rm -f /tmp/ezrand.txt
for i in {1..1000}; do ./ez -R; done >> /tmp/ezrand.txt 
python3 testrand.py /tmp/ezrand.txt
