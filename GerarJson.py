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
from tkinter import ttk


class Application:
    def __init__(self, master=None):
        self.lista_tipo = ["Perfil","Configuração", "Adicional"]
        self.comandos_intocaveis = ['>SED50U<;','>SED51U<;','>SED52U<;','>SED53U<;','>SED54U<;','>SED55U<;','>SED56U<;','>SED57U<;','>SED200U<;','>SED201U<;','>SED202U<;']
        self.list_suts = []
        self.list_sucs = []
        self.list_seds = []
        self.lista_removida = []
        self.resto_comandos = []

        for i in range(16):
            self.list_sucs.append('>SUC' + str(i).zfill(2) + 'U<;')

        for i in range(60):
            self.list_suts.append('>SUT' + str(i).zfill(2) + 'U<;')

        for i in range(256):
            self.list_seds.append('>SED' + str(i).zfill(2) + 'U<;')

        Label(root, text= "tipo", background="#dde", foreground="#009", anchor=W).place(x=10,y=10, width=100,height=20)
        self.tipo=ttk.Combobox(root,values=self.lista_tipo )
        self.tipo.bind("<<ComboboxSelected>>", self.pegar)
        self.tipo.focus_set()
        self.tipo.pack(pady=10)

        Label(root, text= "idarquivo", background="#dde", foreground="#009", anchor=W).place(x=10,y=50, width=100,height=20)
        self.idarquivo=Entry(root)
        self.idarquivo.place(x=10,y=70,width=200,height=20)

        Label(root, text= "Versao", background="#dde", foreground="#009", anchor=W).place(x=10,y=90, width=100,height=20)
        self.versao=Entry(root)
        self.versao.place(x=10,y=110,width=200,height=20)

        Label(root, text= "Mifare", background="#dde", foreground="#009", anchor=W).place(x=10,y=130, width=100,height=20)
        self.mifare=Entry(root)
        self.mifare.place(x=10,y=150,width=200,height=20)

        Label(root, text= "Hardware", background="#dde", foreground="#009", anchor=W).place(x=10,y=170, width=100,height=20)
        self.Hardware=Entry(root)
        self.Hardware.place(x=10,y=190,width=200,height=20)

        Label(root, text= "Limite Vel", background="#dde", foreground="#009", anchor=W).place(x=10,y=210, width=100,height=20)
        self.limiteVel=Entry(root)
        self.limiteVel.place(x=10,y=230,width=200,height=20)

        Label(root, text= "Limite Vel Evento", background="#dde", foreground="#009", anchor=W).place(x=10,y=250, width=100,height=20)
        self.limiteEV=Entry(root)
        self.limiteEV.place(x=10,y=270,width=200,height=20)

        Label(root, text= "Tempo Infração", background="#dde", foreground="#009", anchor=W).place(x=10,y=290, width=100,height=20)
        self.TempoInfra=Entry(root)
        self.TempoInfra.place(x=10,y=310,width=200,height=20)

        Label(root, text= "Nome JSON", background="#dde", foreground="#009", anchor=W).place(x=10,y=330, width=100,height=20)
        self.nome=Entry(root)
        self.nome.place(x=10,y=350,width=200,height=20)

        Label(root, text= "Customer Child ID", background="#dde", foreground="#009", anchor=W).place(x=10,y=370, width=100,height=20)
        self.ccid=Entry(root)
        self.ccid.place(x=10,y=390,width=200,height=20)

        Button(root, text="Gerar", command=self.Listas ).place(x=10,y=420,width=80,height=20)

        messagebox.showinfo("Escolha arquivo", "escolher arquivo .txt para gerar o JSON")
        self.path = dlg.askopenfilename()

    def Listas(self):
        f=open(f'{self.path}')
        self.tudo = f.read()
        self.SUCS = sorted(re.findall(r'(>SUC.*<)', self.tudo))
        for i in range(len(self.SUCS)):
            l1 = (re.findall('(>SUC\d{1,})', self.SUCS[i]))
            for k in range(1):    
                l3 = (re.findall('(\d{1,})', l1[k]))
                indice = int(l3[k])
                self.lista_removida.append(self.SUCS[i])
                self.list_sucs[i] = self.SUCS[i] + ';'
                # print(self.list_sucs)


        self.SUTS = sorted(re.findall(r'(>SUT.*<)', self.tudo))
        for i in range(len(self.SUTS)):
            l1 = (re.findall('(>SUT\d{1,})', self.SUTS[i]))
            for k in range(len(l1)):
                l3 = (re.findall('(\d{1,})', l1[k]))
                indice = int(l3[k])
                self.lista_removida.append(self.SUTS[i])
                self.list_suts[indice] =(self.SUTS[i] + ';')

        self.SEDS = sorted(re.findall(r'(>SED.*<)', self.tudo))
        for i in range(len(self.SEDS)):
            l1 = (re.findall('(>SED\d{1,})', self.SEDS[i]))
            for k in range(len(l1)):
                l3 = (re.findall('(\d{1,})', l1[k]))
                indice = int(l3[k])
                self.lista_removida.append(self.SEDS[i])
                self.list_seds[indice] = (self.SEDS[i] + ';')

        for i in range(len(self.comandos_intocaveis)):
            self.list_seds = list(filter((self.comandos_intocaveis[i]).__ne__, self.list_seds))
            self.resto_comandos = re.findall('(>\S.*<)', self.tudo)

        for i in range(len(self.lista_removida)):
            self.resto_comandos = list(filter((self.lista_removida[i]).__ne__, self.resto_comandos))
        # pprint(self.list_seds)
        # pprint(self.list_sucs)
        # pprint(self.list_suts)
        self.GerarJson()
        
                
    def pegar(self,event):
        self.Ttipo2 = self.tipo.get()
        # print(self.Ttipo2)

    def GerarJson(self):
        self.Tidarquivo = '"' + self.idarquivo.get()+ '"'
        self.Ttipo = '"' + self.Ttipo2 + '"'
        self.Thardware = '"' + self.Hardware.get() + '"'
        self.Tversao = '"' + self.versao.get() + '"'
        self.Tmifare = '"' + self.mifare.get() + '"'
        self.TlimiteVel = '"' + self.limiteVel.get() + '"'
        self.TlimiteEV = '"' + self.limiteEV.get() + '"'
        self.TtempoInfra = '"' + self.TempoInfra.get() + '"'
        self.hash = ',"hash":""}'
        self.Jnome = self.nome.get()
        self.cabeçalho = '{"idarquivo":'+self.Tidarquivo+',"tipo":'+self.Ttipo+',"hardware":['+self.Thardware+'],"configs":[{"Versão":'+self.Tversao+'},{"idarquivo":'+self.Tidarquivo+'},{"Mifare":'+self.Tmifare+'},{"limite Vel":'+self.TlimiteVel+'},{"limite Vel Evento":'+self.TlimiteEV+'},{"Tempo Infração":'+self.TtempoInfra+'}],"comandos":"'
        # print(self.cabeçalho)
        self.Criar()
        
    def Criar(self):    
        self.f2=open (f'{self.Jnome}.json','w',encoding='utf-8')
        self.f2.write(self.cabeçalho)
        for i in range(len(self.resto_comandos)):
            self.f2.write(self.resto_comandos[i] + ';')
        for i in range(16):
            self.f2.write(self.list_sucs[i])
        for i in range(60):
            self.f2.write(self.list_suts[i])
        for i in range(len(self.list_seds)):
            self.f2.write(self.list_seds[i])
        self.f2.write('>SSO<"')
        self.f2.write(self.hash)
        self.f2.close()


root = Tk()
root.geometry("230x600")
root.title("DADOS")
root.configure(background="#dde")
a=Application(root)
root.mainloop()