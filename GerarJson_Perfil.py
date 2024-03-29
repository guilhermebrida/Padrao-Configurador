from encodings import utf_8
import re
from pprint import pprint 
from tkinter import filedialog as dlg
import base64
import hashlib
from Crypto.Cipher import AES 
import json
from base64 import b64encode, b64decode
from aes_pkcs5.algorithms.aes_ecb_pkcs5_padding import AESECBPKCS5Padding
from datetime import date



# PERFIL 
list_replace = [' VL12',' VL10',' VC5',' VL6',' VL8']
tipo = 'Perfil'

path = dlg.askopenfilename()
f=open(f'{path}', encoding='utf_8')
tudo = f.read()
buscaS3 = re.search('>TCFG13,9999<', tudo)
buscaS1 = re.search('>SIS8.*<', tudo)
buscaS4 = re.search('>SSB.*<', tudo)

buscaS8 = re.search('VL8', tudo)
if buscaS8 is None:
    buscaS8 = re.search('VL8',path)

path = path.split('/')[-1].split('.')[0]
idarquivo= path.replace('_',' ')
for i in list_replace:
    idarquivo = idarquivo.replace(i,'')





def Json(*args):
    if path is not None:
        idarq='{"idarquivo":"'+idarquivo+'",'
        Jtipo='"tipo":"'+tipo+'",'
        Jhardware='"hardware":["'+hardware+'"],'
        Jversao='"configs":[{"Versão":"'+versao+'"},'
        idarq2='{"idarquivo":"'+idarquivo+'"}'
        cabeçalho=idarq+Jtipo+Jhardware+Jversao+idarq2
        if tablet is not None:
            Jtablet=',{"Modelo Tablet":"'+tablet+'"}'
            cabeçalho=cabeçalho+Jtablet
        Jmifare=',{"Mifare":"'+mifare+'"}'
        cabeçalho = cabeçalho+Jmifare
        if lim_vel is not None:
            limiteVel=',{"limite Vel":"'+lim_vel+'"}'
            cabeçalho=cabeçalho+limiteVel
        if vel_evento is not None:
            velEvento=',{"limite Vel Evento":"'+vel_evento+'"}'
            cabeçalho=cabeçalho+velEvento
        if tempo_infra is not None:
            tempoInfra=',{"Tempo Infração":"'+tempo_infra+'"}'
            cabeçalho=cabeçalho+tempoInfra
        comandos='],"comandos":"'
        cabeçalho=cabeçalho+comandos
    return cabeçalho


def Criar(*args):
    f2=open (f'{path}.json','w',encoding='utf-8')
    f2.write(cabeçalho)
    for i in range(len(resto_comandos)):
        f2.write(resto_comandos[i] + ';')
    for i in range(16):
        f2.write(list_sucs[i])
    for i in range(len(list_suts)):
        f2.write(list_suts[i])
    for i in range(len(list_seds)):
        f2.write(list_seds[i])
    if SCC58 is not None:
        f2.write(SCC58)
        f2.write(';')
    f2.write('>SSO<"')
    hash = ',"hash":""}'
    f2.write(hash)
    f2.close()


def message():
    f=open(f'{path}.json',encoding='utf_8')
    json_data=f.read()
    json_dict = json.loads(json_data)
    comandos=json_dict['comandos']
    return comandos


class AES_pkcs5:
    def __init__(self,key:str, mode:AES.MODE_CBC=AES.MODE_CBC,block_size:int=16):
        self.key = self.setKey(key)
        self.mode = mode
        self.block_size = block_size



    def pad(self,byte_array:bytearray):
        pad_len = (self.block_size - len(byte_array) % self.block_size) *  chr(self.block_size - len(byte_array) % self.block_size)
        return byte_array.decode() +pad_len
    

    def unpad(self,byte_array:bytearray):
        return byte_array[:-ord(byte_array[-1:])]


    def setKey(self,key:str):
        self.key = key.encode('utf-8')
        md5 = hashlib.md5
        self.key = md5(self.key).digest()[:16]
        self.key = self.key.zfill(16)
        return self.key

    def encrypt(self,message:str)->str:
        iv = bytearray([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        byte_array = message.encode("UTF-8")
        padded = self.pad(byte_array)
        cipher = AES.new(self.key, AES.MODE_CBC,iv)
        encrypted = cipher.encrypt(padded.encode())
        encrypted64 = base64.b64encode(encrypted).decode('utf-8')
        f=open(f'{path}.json',encoding='utf_8')
        json_data=f.read()
        json_dict = json.loads(json_data)
        comandos=json_dict['comandos']
        json_dict.update(comandos=encrypted64)
        json_dict.update(hash=base64.b64encode(self.key).decode('utf-8'))
        f = open(f'{path}.json', 'w',encoding='utf-8')
        json.dump(json_dict, f,ensure_ascii=False)



if buscaS3 is not None:
    print(buscaS3.group(), '\nÉ S3+')
    comandos_intocaveis = ['>SED10U<;','>SED11U<;','>SED12U<;','>SED13U<;','>SED22U<;','>SED23U<;','>SED38U<;','>SED39U<;','>SED45U<;','>SED50U<;','>SED51U<;','>SED52U<;','>SED53U<;','>SED54U<;','>SED55U<;','>SED56U<;','>SED57U<;','>SED200U<;','>SED77U<;','>SED78U<;','>SED119U<;','>SED127U<;','>SED138U<;','>SED139U<;','>SED201U<;','>SED202U<;','>SED203U<;','>SED204U<;','>SED205U<;','>SED211U<;','>SED212U<;','>SED213U<;','>SED214U<;']
    suts_intocaveis = ['>SUT02U<;','>SUT07U<;','>SUT27U<;','>SUT58U<;','>SUT59U<;']
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

    tudo = re.sub('//.*','', tudo)      
    SUCS = sorted(re.findall(r'(>SUC.*<)', tudo))
    for i in range(len(SUCS)):
        l1 = (re.findall('(>SUC\d{1,})', SUCS[i]))
        for k in range(1):    
            l3 = (re.findall('(\d{1,})', l1[k]))
            indice = int(l3[k])
            lista_removida.append(SUCS[i])
            list_sucs[i] = SUCS[i] + ';'

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
        
    SCC58 = re.search('>SCC58.*<',tudo)
    if SCC58 is not None:
        SCC58 = re.search('>SCC58.*<',tudo).group()


    for i in range(len(comandos_intocaveis)):
        list_seds = list(filter((comandos_intocaveis[i]).__ne__, list_seds))
        resto_comandos = re.findall('(>\S.*<)', tudo)

    for i in range(len(suts_intocaveis)):
        list_suts = list(filter((suts_intocaveis[i]).__ne__,list_suts))

    for i in range(len(lista_removida)):
        resto_comandos = list(filter((lista_removida[i]).__ne__, resto_comandos))



    ##### VARIAVEIS PARA CABEÇALHO 
    tipo = 'Perfil'
    hardware = 'VIRLOC12'


    lim_vel= re.search('>SCT11.*<',tudo)
    if lim_vel is not None:
        lim_vel= re.search('>SCT11.*<',tudo).group()[7:-1]
        if str(len(lim_vel)) == '5':
            lim_vel = lim_vel[0:2]
        else:
            lim_vel = lim_vel[0:3]

    

    vel_evento= re.search('>SCT12.*<',tudo)
    if vel_evento is not None:
        vel_evento= re.search('>SCT12.*<',tudo).group()[7:-1]
        if str(len(vel_evento)) == '5':
            vel_evento = vel_evento[0:2]
        if str(len(vel_evento)) == '6':
            vel_evento = vel_evento[0:3]



    tempo_infra= re.search('>SCT06.*<',tudo)
    if tempo_infra is not None:
        tempo_infra= re.search('>SCT06.*<',tudo).group()[7:-1]



    mifare= re.search('>SSH11.*<',tudo)
    if mifare is not None:
        mifare= re.search('>SSH11.*<',tudo).group()[6]
        if mifare == '1':
            mifare = 'Habilitado'
        else:
            mifare = 'Desabilitado'
    else:
        mifare = 'Desabilitado' 


    versao= re.search('>STP01.*<',tudo)
    if versao is not None:
        versao1 = re.search('-+',versao.group())
        if versao1 is None:
            versao1= re.search('>STP01.*<',tudo).group()
            versao1= re.search('\d\d\d\d*',versao1).group()
            versao = versao1
    else:
        versao = re.search('>STP03.*<',tudo)
        if versao is not None:
            versao2 = re.search('-+',versao.group())
            if versao2 is None:
                versao2= re.search('\d\d\d\d*',versao.group()).group()
                versao = versao2
    



    tablet = re.search('>SED169.*<', tudo)
    if tablet is not None:
        tablet = re.search('>SED169.*<', tudo).group()
        tabletN77 = re.search('TRM', tablet)
        if tabletN77 is not None:
            tablet = 'N776/N77'
        tabletSAM = re.search('VCM_SL', tablet)
        if tabletSAM is not None:
            tablet = 'SAMSUNG'
        SEMtablet = re.search('SGN NN', tablet)
        if SEMtablet is not None:
            tablet = None
        

    
elif buscaS1 is not None:
    print(buscaS1.group(), '\nÉ S1')
        
    comandos_intocaveis = ['>SED00U<;','>SED01U<;','>SED02U<;','>SED03U<;','>SED04U<;','>SED05U<;','>SED06U<;','>SED07U<;','>SED08U<;','>SED000U<;','>SED001U<;','>SED002U<;','>SED003U<;','>SED004U<;','>SED005U<;','>SED006U<;','>SED007U<;','>SED008U<;','>SED99U<;']
    list_suts = []
    list_sucs = []
    list_seds = []
    lista_removida = []
    resto_comandos = []
    for i in range(16):
        list_sucs.append('>SUC' + str(i).zfill(2) + 'U<;')

    for i in range(64):
        list_suts.append('>SUT' + str(i).zfill(2) + 'U<;')

    for i in range(256):
        list_seds.append('>SED' + str(i).zfill(2) + 'U<;')

    tudo = re.sub('//.*','', tudo)
    SUCS = sorted(re.findall(r'(>SUC.*<)', tudo))
    for i in range(len(SUCS)):
        l1 = (re.findall('(>SUC\d{1,})', SUCS[i]))
        for k in range(1):    
            l3 = (re.findall('(\d{1,})', l1[k]))
            indice = int(l3[k])
            lista_removida.append(SUCS[i])
            list_sucs[i] = SUCS[i] + ';'
    

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

    SCC58 = re.search('>SCC58.*<',tudo)
    if SCC58 is not None:
        SCC58 = re.search('>SCC58.*<',tudo).group()

    for i in range(len(comandos_intocaveis)):
        list_seds = list(filter((comandos_intocaveis[i]).__ne__, list_seds))
        resto_comandos = re.findall('(>\S.*<)', tudo)

    for i in range(len(lista_removida)):
        resto_comandos = list(filter((lista_removida[i]).__ne__, resto_comandos))

    ##### VARIAVEIS PARA CABEÇALHO 

    hardware = 'VIRLOC6'

    lim_vel= re.search('>VS08,100.*<',tudo)
    if lim_vel is not None:
        lim_vel= re.search('>VS08,100.*<',tudo).group()[10:13]
        if lim_vel[0] == '0':
            lim_vel = re.sub(r'0', '', lim_vel, count = 1)


    

    tempo_infra= re.findall('>SCT06.*<',tudo)
    if ((tempo_infra is not None) and (tempo_infra !='0')):
        tempo_infra= re.findall('>SCT06.*<',tudo)[1]
        tempo_infra = tempo_infra[7:-1]



    mifare= re.search('>SSH11.*<',tudo)
    if mifare is not None:
        mifare= re.search('>SSH11.*<',tudo).group()[6]
        if mifare == '1':
            mifare = 'Habilitado'
        else:
            mifare = 'Desabilitado'
    else:
        mifare = 'Desabilitado' 


    versao= re.search('>SIS82.*<',tudo)
    if versao is not None:
        versao1 = re.search('-',versao.group())
        if versao1 is not None:
            versao1 = re.search('-',versao1.group())
        else:    
            versao1= re.search('>SIS82.*<',tudo).group()
            versao1= re.search('\d\d\d\d*',versao1).group()
            versao = versao1
    else:
        versao = re.search('>SIS84.*<',tudo)
        if versao is not None:
            versao2 = re.search('>SIS84.*<',tudo).group()
            if versao2 != '-':
                versao2= re.search('\d\d\d\d*',versao2).group()
                versao= versao2
     

    vel_evento = None
    tablet = None

    
        
elif buscaS4 is not None:
    print(buscaS4.group(), '\nÉ S4/S7')
    comandos_intocaveis = ['>SED02U<;','>SED03U<;','>SED04U<;','>SED05U<;','>SED10U<;','>SED11U<;','>SED12U<;','>SED13U<;','>SED22U<;','>SED23U<;','>SED38U<;','>SED39U<;','>SED45U<;','>SED50U<;','>SED51U<;','>SED52U<;','>SED53U<;','>SED54U<;','>SED55U<;','>SED56U<;','>SED57U<;','>SED200U<;','>SED77U<;','>SED78U<;','>SED119U<;','>SED127U<;','>SED138U<;','>SED139U<;','>SED201U<;','>SED202U<;','>SED203U<;','>SED204U<;','>SED205U<;','>SED211U<;','>SED212U<;','>SED213U<;','>SED214U<;']
    suts_intocaveis = ['>SUT02U<;','>SUT07U<;','>SUT22U<;','>SUT23U<;','>SUT27U<;','>SUT58U<;','>SUT59U<;']
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

    tudo = re.sub('//.*','', tudo)
    SUCS = sorted(re.findall(r'(>SUC.*<)', tudo))
    for i in range(len(SUCS)):
        l1 = (re.findall('(>SUC\d{1,})', SUCS[i]))
        for k in range(1):    
            l3 = (re.findall('(\d{1,})', l1[k]))
            indice = int(l3[k])
            lista_removida.append(SUCS[i])
            list_sucs[i] = SUCS[i] + ';'

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


    SCC58 = re.search('>SCC58.*<',tudo)
    if SCC58 is not None:
        SCC58 = re.search('>SCC58.*<',tudo).group()

    for i in range(len(comandos_intocaveis)):
        list_seds = list(filter((comandos_intocaveis[i]).__ne__, list_seds))
        resto_comandos = re.findall('(>\S.*<)', tudo)

    for i in range(len(suts_intocaveis)):
        list_suts = list(filter((suts_intocaveis[i]).__ne__,list_suts))

    for i in range(len(lista_removida)):
        resto_comandos = list(filter((lista_removida[i]).__ne__, resto_comandos))


    tipo = 'Perfil'
    hardware = 'VIRCOM5'


    lim_vel= re.search('>SCT11.*<',tudo)
    if lim_vel is not None:
        lim_vel= re.search('>SCT11.*<',tudo).group()[7:-1]
        if str(len(lim_vel)) == '5':
            lim_vel = lim_vel[0:2]
        else:
            lim_vel = lim_vel[0:3]

    

    vel_evento= re.search('>SCT12.*<',tudo)
    if vel_evento is not None:
        vel_evento= re.search('>SCT12.*<',tudo).group()[7:-1]
        if str(len(vel_evento)) == '5':
            vel_evento = vel_evento[0:2]
        if str(len(vel_evento)) == '6':
            vel_evento = vel_evento[0:3]



    tempo_infra= re.search('>SCT06.*<',tudo)
    if tempo_infra is not None:
        tempo_infra= re.search('>SCT06.*<',tudo).group()[7:-1]


    mifare= re.search('>SSH11.*<',tudo)
    if mifare is not None:
        mifare= re.search('>SSH11.*<',tudo).group()[6]
        if mifare == '1':
            mifare = 'Habilitado'
        else:
            mifare = 'Desabilitado'
    else:
        mifare = 'Desabilitado'

    versao= re.search('>STP01.*<',tudo)
    if versao is not None:
        versao1 = re.search('-+',versao.group())
        if versao1 is None:
            versao1= re.search('>STP01.*<',tudo).group()
            versao1= re.search('\d\d\d\d*',versao1).group()
            versao= versao1
    else:
        versao = re.search('>STP03.*<',tudo)
        if versao is not None:
            versao2 = re.search('-+',versao.group())
            if versao2 is None:
                versao2= re.search('\d\d\d\d*',versao.group()).group()
                versao = versao2

    tablet = None


elif buscaS8 is not None:
    print(buscaS8.group(), '\n É S8')
    comandos_intocaveis = ['>SED10U<;','>SED11U<;','>SED12U<;','>SED13U<;','>SED22U<;','>SED23U<;','>SED38U<;','>SED39U<;','>SED45U<;','>SED50U<;','>SED51U<;','>SED52U<;','>SED53U<;','>SED54U<;','>SED55U<;','>SED56U<;','>SED57U<;','>SED200U<;','>SED77U<;','>SED78U<;','>SED119U<;','>SED127U<;','>SED138U<;','>SED139U<;','>SED201U<;','>SED202U<;','>SED203U<;','>SED204U<;','>SED205U<;','>SED206U<;','>SED211U<;','>SED212U<;','>SED213U<;','>SED214U<;']
    suts_intocaveis = ['>SUT02U<;','>SUT07U<;','>SUT27U<;','>SUT50U<;','>SUT58U<;','>SUT59U<;']
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

    tudo = re.sub('//.*','', tudo)
        
    SUCS = sorted(re.findall(r'(>SUC.*<)', tudo))
    for i in range(len(SUCS)):
        l1 = (re.findall('(>SUC\d{1,})', SUCS[i]))
        for k in range(1):    
            l3 = (re.findall('(\d{1,})', l1[k]))
            indice = int(l3[k])
            lista_removida.append(SUCS[i])
            list_sucs[i] = SUCS[i] + ';'

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
    
    SCC58 = re.search('>SCC58.*<',tudo)
    if SCC58 is not None:
        SCC58 = re.search('>SCC58.*<',tudo).group()

    for i in range(len(comandos_intocaveis)):
        list_seds = list(filter((comandos_intocaveis[i]).__ne__, list_seds))
        resto_comandos = re.findall('(>\S.*<)', tudo)

    for i in range(len(suts_intocaveis)):
        list_suts = list(filter((suts_intocaveis[i]).__ne__,list_suts))

    for i in range(len(lista_removida)):
        resto_comandos = list(filter((lista_removida[i]).__ne__, resto_comandos))


    ##### VARIAVEIS PARA CABEÇALHO 
    hardware = 'VIRLOC8'

    lim_vel= re.search('>SCT11.*<',tudo)
    if lim_vel is not None:
        lim_vel= re.search('>SCT11.*<',tudo).group()[7:-1]
        if str(len(lim_vel)) == '5':
            lim_vel = lim_vel[0:2]
        else:
            lim_vel = lim_vel[0:3]

    

    vel_evento= re.search('>SCT12.*<',tudo)
    if vel_evento is not None:
        vel_evento= re.search('>SCT12.*<',tudo).group()[7:-1]
        if str(len(vel_evento)) == '5':
            vel_evento = vel_evento[0:2]
        if str(len(vel_evento)) == '6':
            vel_evento = vel_evento[0:3]



    tempo_infra= re.search('>SCT06.*<',tudo)
    if tempo_infra is not None:
        tempo_infra= re.search('>SCT06.*<',tudo).group()[7:-1]



    mifare= re.search('>SSH11.*<',tudo)
    if mifare is not None:
        mifare= re.search('>SSH11.*<',tudo).group()[6]
        if mifare == '1':
            mifare = 'Habilitado'
        else:
            mifare = 'Desabilitado'
    else:
        mifare = 'Desabilitado' 

    
    versao= re.search('>STP01.*<',tudo)
    if versao is not None:
        versao1 = re.search('-+',versao.group())
        if versao1 is None:
            versao1= re.search('>STP01.*<',tudo).group()
            versao1= re.search('\d\d\d\d*',versao1).group()
            versao = versao1
    if versao is None:
        versao = re.search('>STP03.*<',tudo)
        if versao is not None:
            versao2 = re.search('-+',versao.group())
            if versao2 is None:
                versao2= re.search('\d\d\d\d*',versao.group()).group()
                versao = versao2
    # versao =None
    # if versao is None:
    #     versao = str(date.today())
    #     versao = versao.replace('-','')[-6::]
    


    tablet = re.search('>SED169.*<', tudo)
    if tablet is not None:
        tablet = re.search('>SED169.*<', tudo).group()
        tabletN77 = re.search('TRM', tablet)
        if tabletN77 is not None:
            tablet = 'N776/N77'
        tabletSAM = re.search('VCM_SL', tablet)
        if tabletSAM is not None:
            tablet = 'SAMSUNG'
        SEMtablet = re.search('SGN NN', tablet)
        if SEMtablet is not None:
            tablet = None
    
    

else:
    print('É S3')
    comandos_intocaveis = ['>SED10U<;','>SED11U<;','>SED12U<;','>SED13U<;','>SED22U<;','>SED23U<;','>SED38U<;','>SED39U<;','>SED45U<;','>SED50U<;','>SED51U<;','>SED52U<;','>SED53U<;','>SED54U<;','>SED55U<;','>SED56U<;','>SED57U<;','>SED200U<;','>SED77U<;','>SED78U<;','>SED119U<;','>SED127U<;','>SED138U<;','>SED139U<;','>SED201U<;','>SED202U<;','>SED203U<;','>SED204U<;','>SED205U<;','>SED211U<;','>SED212U<;','>SED213U<;','>SED214U<;']
    suts_intocaveis = ['>SUT02U<;','>SUT07U<;','>SUT27U<;','>SUT58U<;','>SUT59U<;']
    list_suts = []
    list_sucs = []
    list_seds = []
    lista_removida = []
    resto_comandos = []

    for i in range(16):
        list_sucs.append('>SUC' + str(i).zfill(2) + 'U<;')
    print(list_sucs)

    for i in range(60):
        list_suts.append('>SUT' + str(i).zfill(2) + 'U<;')

    for i in range(256):
        list_seds.append('>SED' + str(i).zfill(2) + 'U<;')

    tudo = re.sub('//.*','', tudo) 
    SUCS = sorted(re.findall(r'(>SUC.*<)', tudo))
    print(SUCS)
    for i in range(len(SUCS)):
        l1 = (re.findall('(>SUC\d{1,})', SUCS[i]))
        print(l1)
        for k in range(len(l1)):    
            l3 = (re.findall('(\d{1,})', l1[k]))
            indice = int(l3[k])
            lista_removida.append(SUCS[i])
            list_sucs[i] = SUCS[i] + ';'
    print(list_sucs)

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
        
    SCC58 = re.search('>SCC58.*<',tudo)
    if SCC58 is not None:
        SCC58 = re.search('>SCC58.*<',tudo).group()

    for i in range(len(comandos_intocaveis)):
        list_seds = list(filter((comandos_intocaveis[i]).__ne__, list_seds))
        resto_comandos = re.findall('(>\S.*<)', tudo)

    for i in range(len(suts_intocaveis)):
        list_suts = list(filter((suts_intocaveis[i]).__ne__,list_suts))

    for i in range(len(lista_removida)):
        resto_comandos = list(filter((lista_removida[i]).__ne__, resto_comandos))



    ##### VARIAVEIS PARA CABEÇALHO 
    hardware = 'VIRLOC10"'+','+'"VIRLOC11'

    lim_vel= re.search('>SCT11.*<',tudo)
    if lim_vel is not None:
        lim_vel= re.search('>SCT11.*<',tudo).group()[7:-1]
        if str(len(lim_vel)) == '5':
            lim_vel = lim_vel[0:2]
        else:
            lim_vel = lim_vel[0:3]

    

    vel_evento= re.search('>SCT12.*<',tudo)
    if vel_evento is not None:
        vel_evento= re.search('>SCT12.*<',tudo).group()[7:-1]
        if str(len(vel_evento)) == '5':
            vel_evento = vel_evento[0:2]
        if str(len(vel_evento)) == '6':
            vel_evento = vel_evento[0:3]



    tempo_infra= re.search('>SCT06.*<',tudo)
    if tempo_infra is not None:
        tempo_infra= re.search('>SCT06.*<',tudo).group()[7:-1]


    mifare= re.search('>SSH11.*<',tudo)
    if mifare is not None:
        mifare= re.search('>SSH11.*<',tudo).group()[6]
        if mifare == '1':
            mifare = 'Habilitado'
        else:
            mifare = 'Desabilitado'
    else:
        mifare = 'Desabilitado'      



    versao= re.search('>STP01.*<',tudo)
    if versao is not None:
        versao1 = re.search('-+',versao.group())
        if versao1 is None:
            versao1= re.search('>STP01.*<',tudo).group()
            versao1= re.search('\d\d\d\d*',versao1).group()
            versao = versao1
    else:
        versao = re.search('>STP03.*<',tudo)
        if versao is not None:
            versao2 = re.search('-+',versao.group())
            if versao2 is None:
                versao2= re.search('\d\d\d\d*',versao.group()).group()
                versao=versao2
    if versao is None:
        versao = str(date.today())
        versao = versao.replace('-','')[-6::]




    tablet = re.search('>SED169.*<', tudo)
    if tablet is not None:
        tablet = re.search('>SED169.*<', tudo).group()
        tabletN77 = re.search('TRM', tablet)
        if tabletN77 is not None:
            tablet = 'N776/N77'
        tabletSAM = re.search('VCM_SL', tablet)
        if tabletSAM is not None:
            tablet = 'SAMSUNG'
        SEMtablet = re.search('SGN NN', tablet)
        if SEMtablet is not None:
            tablet = None
    
if __name__ == '__main__':
    cabeçalho = Json()
    Criar()
    comandos=message()
    AES_pkcs5_obj= AES_pkcs5(comandos)
    encrypted_message = AES_pkcs5_obj.encrypt(comandos)



