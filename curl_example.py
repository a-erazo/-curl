#!/usr/bin/python
# Este archivo usa el encoding: utf-8
#TODO: verificar Curl command
import datetime
import rsa
import json
import base64
import urllib2 
import os
import sys
import re
import time
import shlex
import subprocess

#URL = "https://bicis-server.com"
#uri = "/api/v1/measure"
#URL = "168.176.26.28/sensores_iot"
#uri = "/php/registrar.php"


#----------------------------------------------------------------------------------------
#                                 clases
#----------------------------------------------------------------------------------------
class Measure:
  def __init__(self):
    self.value = 10.1#"10.1"
    self.timestamp = getCurrentTimeStamp()
    self.tipo = "Noise" #"IN" # IN  OUT

#----------------------------------------------------------------------------------------
class Sensor:
  def __init__(self):
    self.Id = "1" #"5689792285114368 " #IMPORTANTE, debe coincidir con el de la plataforma
    self.ref = "tempAct" #Cualquier string es valido
    self.latitude = 4.7
    self.longitude = -74.0
    self.statusCode = "OK"

#----------------------------------------------------------------------------------------
class Gateway:
  def __init__(self):
    self.Id = "1"#IMPORTANTE, debe coincidir con el de la plataforma
    self.latitude = 4.7
    self.longitude = -74.0
    self.statusCode = "OK"
#    self.dateGateway = getCurrentTimeStamp() 
    self.privKey = self.getPrivKey()

  def getPrivKey(self):
    with open('/home/debian/rfid_temp/src/privateKey.pem', 'r') as privatefile: #Aqui se debe poner el path a la PEM creada con openssl
      keydata = privatefile.read()
      privKey = rsa.PrivateKey.load_pkcs1(keydata)
    return privKey

#----------------------------------------------------------------------------------------
#                                 Functions
#----------------------------------------------------------------------------------------


#----------------------------------------------------------------------------------------
def getCurrentTimeStamp():
  return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S000Z")
#  return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

#----------------------------------------------------------------------------------------
def createSubPayload(measure):
  payload = {"value":measure.value,
     "timestamp": measure.timestamp,
     "tipo": measure.tipo }
  return "%s"%(json.dumps(payload))
#----------------------------------------------------------------------------------------
def createPayload( bufferMeasures, gatewayId, sensorId ): 
  """
  it creates payload for the sensor and buffer of Measures
  """
  listSubPayloads = [] # A subPayload is all the info into {} and contains all the info from a determined measure
  for x in xrange(0,len(bufferMeasures)): # for all measures begin this in cero
    imeasure = bufferMeasures.pop()
    isubPayload=createSubPayload(imeasure)
    listSubPayloads.append(isubPayload)

  payload ="[{\"gatewayId\":\"%s\", \"sensorId\":\"%s\"}," % (gatewayId, sensorId) # payload concatenates all the subPayload into one payload
  limit=len(listSubPayloads)
  for x in xrange(0,limit):
    if (x==limit-1): payload = payload + listSubPayloads.pop() + " ]"
    else: payload = payload + listSubPayloads.pop() + " ,"

  return payload

#----------------------------------------------------------------------------------------
def createCanonicalRequest(payload, timestamp, URL, uri):
  canonicalRequest = "%s%s\n%s\n%s\n%s\n" % (URL, uri, "POST", payload, timestamp)
  return canonicalRequest

#----------------------------------------------------------------------------------------
def createSignature(canonicalRequest, gt):
  signature_str = rsa.sign(canonicalRequest.encode('utf8') , gt.privKey, 'SHA-256')
  return base64.b64encode(signature_str)

#----------------------------------------------------------------------------------------
def createCurlCommand(signature, timestamp, gatewayId, payload, URL, uri):
  curlCommand = "curl -X POST --header \"content-type: application/json\" --header \"x-signature-timestamp: %s\" --header \"authorization: ID=%s, Signature=%s\" -d \'%s\' -v %s%s" % ( timestamp, gatewayId, signature, payload, URL, uri)
  return curlCommand

#----------------------------------------------------------------------------------------
#                                 main
#----------------------------------------------------------------------------------------

URL1 = "https://pruebas-iot.appspot.com"
uri1 = "/register"
URL2 = "168.176.26.28"
uri2 = "/sensores_iot/php/registrar.php"

v = 0 # verbose output
path = "/home/debian/rfid_temp/src/send2IoTServer.fifo"

print "\n---------------------->Initiating send2IoTServer.py<----------------------------\n"

tempAct = Sensor()
gt1 = Gateway()
measure1 = Measure()


while True:

  fifo = open(path, "r")
  data = fifo.read()
  if (v==1): print data
  fifo.close()
  datos = re.split(' +', data)

  if(1):

    #measure.TID = "123456789ABC"
#    tempAct.Id = datos[0] # sensorId
    if (datos[0]=="BBBBFF000023"): tempAct.Id = "04"
    if (datos[0]=="BBBBFF000026"): tempAct.Id = "05"
    if (datos[0]=="BBBBFF000040"): tempAct.Id = "06"
    if (datos[0]=="BBBBFF000051"): tempAct.Id = "09"
    measure1.timestamp = getCurrentTimeStamp()
#    measure1.tipo = datos[1] # tipo temp
    measure1.tipo = "Temperatura" # tipo temp
    measure1.value = float(datos[2]) # value
    #measure.io = 1

    bufferMeasures = []
    bufferMeasures.append(measure1)

    gatewayId = gt1.Id
    sensorId = tempAct.Id
    payload = createPayload(bufferMeasures, gatewayId, sensorId)
    if v: print "\n--->payload: \n"+payload
    timestamp = getCurrentTimeStamp()

    #curl_1:

    cr = createCanonicalRequest(payload,timestamp, URL1, uri1)
    if v: print "\n--->canonicalRequest: \n"+cr

    sig = createSignature(cr,gt1)
    if v: print "\n--->Signature: \n"+sig

    curlCommand = createCurlCommand(sig, timestamp, gatewayId, payload, URL1, uri1)
    if 1: print "\n--->curlCommand:\n"+curlCommand
    os.system(curlCommand)


    #curl_2:

    cr = createCanonicalRequest(payload,timestamp, URL2, uri2)
    if v: print "\n--->canonicalRequest: \n"+cr

    sig = createSignature(cr,gt1)
    if v: print "\n--->Signature: \n"+sig

    curlCommand = createCurlCommand(sig, timestamp, gatewayId, payload, URL2, uri2)
    if 1: print "\n--->curlCommand:\n"+curlCommand
    os.system(curlCommand)
