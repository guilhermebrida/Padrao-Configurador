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
lista_comandos = []

path = dlg.askopenfilename()
f=open(f'{path}', encoding='utf_8')
tudo = f.read()
tudo = re.sub('/.*','', tudo)
comandos = (re.findall('>.*<',tudo))
for i in range(len(comandos)):
    if i != (len(comandos)-1):
        lista_comandos.append(comandos[i]+';')
    if i == (len(comandos)-1):
        lista_comandos.append(comandos[i])

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
    for i in range(len(lista_comandos)):
        f2.write(lista_comandos[i]) 
    f2.write('"')
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
    ##### VARIAVEIS PARA CABEÇALHO 
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
