# -*- coding: utf-8 -*-

from difflib import Match
import re
from pprint import pprint 
import collections
import sys

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

# pprint(list_seds)
with open('ARQUIVO.txt') as f:
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


# for i in range(len(resto_comandos)):
#     l2 = re.findall('(>\S.*<)', str(resto_comandos[i]))

for i in range(len(lista_removida)):
    resto_comandos = list(filter((lista_removida[i]).__ne__, resto_comandos))




# "idarquivo":"Nepomuceno RS","tipo":"Perfil","hardware":["VIRLOC12"],"configs":[{"Versão":"220812"},{"idarquivo":"Nepomuceno RS"},{"Mifare":"Habilitado"},{"Lim Vel":"75"},{"Lim Vel Evento":"70"},{"Tempo infração":"5"}],"comandos":"

idarquivo = input('idarquivo: ')
idarquivo = '"' + idarquivo + '"'

tipo = input('tipo: ')
tipo = '"' + tipo + '"'

hardware = input('hardware: ')
hardware = '["' + hardware + '"]'

Versao = input('Versão: ')
Versao = '"' + Versao + '"'

Mifare = input('Mifare: ')
Mifare = '"' + Mifare + '"'

limite_vel = input('Limite Vel: ')
limite_vel = '"' + limite_vel + '"'

limite_vel_evento = input('Limite Vel Evento: ')
limite_vel_evento = '"' + limite_vel_evento + '"'

tempo_infra = input('Tempo infração: ')
tempo_infra = '"' + tempo_infra + '"'

hash = ',"hash":""}'


cabeçalho = '{"idarquivo":'+idarquivo+',"tipo":'+tipo+',"hardware":'+hardware+',"configs":[{"Versão":'+Versao+'},{"idarquivo":'+idarquivo+'},{"Mifare":'+Mifare+'},{"limite Vel":'+limite_vel+'},{"limite Vel Evento":'+limite_vel_evento+'},{"Tempo Infração":'+tempo_infra+'}],"comandos":"'


# cabeçalho = cabeçalho.decode('utf8')
# print(cabeçalho)
with open ('lista2.json','w',encoding='utf-8') as f2:
    f2.write(cabeçalho)
    for i in range(len(resto_comandos)):
        f2.write(resto_comandos[i] + ';')
    for i in range(16):
        f2.write(list_sucs[i])
    for i in range(60):
        f2.write(list_suts[i])
    for i in range(len(list_seds)):
        f2.write(list_seds[i])
    f2.write('>SS0<')
    f2.write(hash)


