Set obj1=createobject("wscript.shell")
obj1.run "cmd /k mitmdump -q -p 7070 -s addons1.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure"
Set obj2=createobject("wscript.shell")
obj2.run "cmd /k mitmdump -q -p 9090 -s addons2.py --ssl-insecure"