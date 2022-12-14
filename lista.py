from cProfile import label
from distutils.cmd import Command
from tkinter import filedialog as dlg
from tkinter import *
from difflib import Match
import re
from pprint import pprint 
import collections
import sys
from tkinter import messagebox

comandos_intocaveis = ['>SED50U<;','>SED51U<;','>SED52U<;','>SED53U<;','>SED54U<;','>SED55U<;','>SED56U<;','>SED57U<;','>SED200U<;','>SED201U<;','>SED202U<;']
list_suts = []
list_sucs = []
list_seds = []
lista_removida = []
resto_comandos = []

for i in range(16):
    list_sucs.append('>SUC' + str(i).zfill(2) + 'U<;')

for i in range(60):
    list_suts.append('>SUT' + str(i).zfill(2) + 'U<;')

for i in range(256):
    list_seds.append('>SED' + str(i).zfill(2) + 'U<;')



def GerarJson():
    global cabeçalho
    Tidarquivo = ('"' + idarquivo.get() + '"')
    Ttipo = ('"' + tipo.get() + '"')
    Thardware = ('"' + Hardware.get() + '"')
    Tversao = ('"' + versao.get() + '"')
    Tmifare = ('"' + mifare.get() + '"')
    TlimiteVel = ('"' + limiteVel.get() + '"')
    TlimiteEV = ('"' + limiteEV.get() + '"')
    TtempoInfra = ('"' + TempoInfra.get() + '"')
    hash = ',"hash":""}'
    Jnome = nome.get()
    cabeçalho = '{"idarquivo":'+Tidarquivo+',"tipo":'+Ttipo+',"hardware":['+Thardware+'],"configs":[{"Versão":'+Tversao+'},{"idarquivo":'+Tidarquivo+'},{"Mifare":'+Tmifare+'},{"limite Vel":'+TlimiteVel+'},{"limite Vel Evento":'+TlimiteEV+'},{"Tempo Infração":'+TtempoInfra+'}],"comandos":"'
    with open (f'{Jnome}.json','w',encoding='utf-8') as f2:
        f2.write(cabeçalho)
        for i in range(len(resto_comandos)):
            f2.write(resto_comandos[i] + ';')
        for i in range(16):
            f2.write(list_sucs[i])
        for i in range(60):
            f2.write(list_suts[i])
        for i in range(len(list_seds)):
            f2.write(list_seds[i])
        f2.write('>SSO<')
        f2.write(hash)
    


root = Tk()
root.geometry("230x400")
root.title("DADOS")
root.configure(background="#dde")

Label(root, text= "idarquivo", background="#dde", foreground="#009", anchor=W).place(x=10,y=10, width=100,height=20)
idarquivo=Entry(root)
idarquivo.place(x=10,y=30,width=200,height=20)

Label(root, text= "Tipo", background="#dde", foreground="#009", anchor=W).place(x=10,y=50, width=100,height=20)
tipo=Entry(root)
tipo.place(x=10,y=70,width=200,height=20)

Label(root, text= "Versao", background="#dde", foreground="#009", anchor=W).place(x=10,y=90, width=100,height=20)
versao=Entry(root)
versao.place(x=10,y=110,width=200,height=20)

Label(root, text= "Mifare", background="#dde", foreground="#009", anchor=W).place(x=10,y=130, width=100,height=20)
mifare=Entry(root)
mifare.place(x=10,y=150,width=200,height=20)

Label(root, text= "Hardware", background="#dde", foreground="#009", anchor=W).place(x=10,y=170, width=100,height=20)
Hardware=Entry(root)
Hardware.place(x=10,y=190,width=200,height=20)

Label(root, text= "Limite Vel", background="#dde", foreground="#009", anchor=W).place(x=10,y=210, width=100,height=20)
limiteVel=Entry(root)
limiteVel.place(x=10,y=230,width=200,height=20)

Label(root, text= "Limite Vel Evento", background="#dde", foreground="#009", anchor=W).place(x=10,y=250, width=100,height=20)
limiteEV=Entry(root)
limiteEV.place(x=10,y=270,width=200,height=20)

Label(root, text= "Tempo Infração", background="#dde", foreground="#009", anchor=W).place(x=10,y=290, width=100,height=20)
TempoInfra=Entry(root)
TempoInfra.place(x=10,y=310,width=200,height=20)

Label(root, text= "Nome JSON", background="#dde", foreground="#009", anchor=W).place(x=10,y=330, width=100,height=20)
nome=Entry(root)
nome.place(x=10,y=350,width=200,height=20)


Button(root, text="Gerar", command=GerarJson ).place(x=10,y=370,width=80,height=20)

messagebox.showinfo("Escolha arquivo", "escolher arquivo .txt para gerar o JSON")
path = dlg.askopenfilename()            
with open(f'{path}') as f:
    tudo = f.read()
SUCS = sorted(re.findall(r'(>SUC.*<)', tudo))
for i in range(len(SUCS)):
    l1 = (re.findall('(>SUC\d{1,})', SUCS[i]))
    for k in range(len(l1)):
        l3 = (re.findall('(\d{1,})', l1[k]))
        indice = int(l3[k])
        lista_removida.append(SUCS[i])
        list_sucs[indice] = (SUCS[i] + ';')

SUTS = sorted(re.findall(r'(>SUT.*<)', tudo))
for i in range(len(SUTS)):
    l1 = (re.findall('(>SUT\d{1,})', SUTS[i]))
    for k in range(len(l1)):
        l3 = (re.findall('(\d{1,})', l1[k]))
        indice = int(l3[k])
        lista_removida.append(SUTS[i])
        list_suts[indice] =(SUTS[i] + ';')

SEDS = sorted(re.findall(r'(>SED.*<)', tudo))
for i in range(len(SEDS)):
    l1 = (re.findall('(>SED\d{1,})', SEDS[i]))
    for k in range(len(l1)):
        l3 = (re.findall('(\d{1,})', l1[k]))
        indice = int(l3[k])
        lista_removida.append(SEDS[i])
        list_seds[indice] = (SEDS[i] + ';')


for i in range(len(comandos_intocaveis)):
    list_seds = list(filter((comandos_intocaveis[i]).__ne__, list_seds))
    resto_comandos = re.findall('(>\S.*<)', tudo)

for i in range(len(lista_removida)):
    resto_comandos = list(filter((lista_removida[i]).__ne__, resto_comandos))

root.mainloop()





