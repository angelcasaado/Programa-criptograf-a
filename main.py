# -*- coding: utf-8 -*-
"""
Created on Wed Oct 19 19:37:41 2022

@author: Ángel Casado Bellisco y Jorfe Francés Fonseca
"""

from cryptography.fernet import Fernet
import sys
import hashlib
import json
import os
import random
import time
import Crypto
from Crypto.PublicKey import RSA
import binascii
from Crypto.Cipher import PKCS1_OAEP

# pep8: disable=E223

# pylint: disable-all


class JsonStore:
    """Superclass for managing storage in JSON files"""
    _ID_FIELD = "_Usuario__usuario"
    _data_list = []

    def __init__(self,h = None):
        if h is None:
            self._FILE_PATH = str(os.getcwd()) + "/json/store"
        else:
            
            self._FILE_PATH = str(os.getcwd()) +"/json/" + h
           
        self.load()

    def load(self):
        """Loading data into the datalist"""
        try:
            with open(self._FILE_PATH, "r", encoding="utf-8", newline="") as file:
                self._data_list = json.load(file)
        except FileNotFoundError:
            # file is not found , so  init my data_list
            self._data_list = []
        except json.JSONDecodeError as exception_raised:
            raise ValueError("JSON Decode Error - Wrong JSON Format") \
                from exception_raised

    def save(self):
        """Saves the datalist in the JSON file"""
        try:
            with open(self._FILE_PATH, "w", encoding="utf-8", newline="") as file:
                json.dump(self._data_list, file, indent=2)
        except FileNotFoundError as ex:
            raise ValueError("Wrong file or file path") from ex

    def add_item(self, item):
        """Adds a new item to the datalist and updates the JSON file"""
        self.load()
        self._data_list.append(item.__dict__)
        self.save()

    def find_item(self, key_value, key=None):
        """Finds the first item with the key_value in the datalist"""
        
        self.load()
       
        if key is None:
            key = self._ID_FIELD
        for item in self._data_list:
            if item[key] == key_value:
                return item
        return None

    def find_items_list(self, key_value, key=None):
        """Finds all the items with the key_value in the datalist"""
        self.load()
        if key is None:
            key = self._ID_FIELD
        data_list_result = []
        for item in self._data_list:
            if item[key] == key_value:
                data_list_result.append(item)
        return data_list_result

    def delete_json_file(self):
        """delete the json file"""
        if os.path.isfile(self._FILE_PATH):
            os.remove(self._FILE_PATH)

    def empty_json_file(self):
        """removes all data from the json file"""
        self._data_list = []
        self.save()

    def data_hash(self):
        """calculates the md5 hash of the file's content"""
        self.load()
        return hashlib.md5(self._data_list.__str__().encode()).hexdigest()

    def update_item(self, key, new_item):
        """modifies one item stored.
        The item is dentified by the key value in the ID_FIELD"""
        self.load()
        # print(key)
        for item in self._data_list:
            # print("->" + item[self._ID_FIELD])
            if item[self._ID_FIELD] == key:
                self._data_list.remove(item)
                self._data_list.append(new_item.__dict__)
                self.save()
                return new_item
        raise ValueError("Update key not found")


class Usuario(): 
    def __init__(self, usuario, contraseña, privada, publica, n = None, e = None, d = None):
        self.__usuario = usuario
        self.__password = contraseña
        self.mensajes = []
        self.mensajes_asimetrticos = []
        self.private = privada
        self.publica = publica
        self.firma = []
        self.n = n
        self.e = e
        self.d = d
        if n == None or e == None or d == None:
            keypair = RSA.generate(bits=1024,e = generatePublic())
            n = encrypt(keypair.n)
            e = encrypt(keypair.e)
            d = encrypt(keypair.d)
            
            self.n = n
            self.e = e
            self.d = d


class ned():
    def __init__(self, n, e, d):
        self.e = e
        self.d = d 
        self.n = n
        
class Key:
    """Clase para la clave de encriptación simétrica"""
    def __init__(self, key):
        self.__key = key
                        


class Public():
        """Clase para claves"""
        def __init__(self, public):
            self.__key = public


def decrypt(m):
    """Función para desencriptar de manera simétrica"""
    token = m.encode("utf-8")
   
    mensaje = f.decrypt(token)
    mensaje = mensaje.decode("utf-8")
    return mensaje


def encrypt(m):
    """Función para encriptar de manera simétrica"""
    m = str(m)
    mensaje = bytes(m, 'utf-8')
    token = f.encrypt(mensaje)

    token = token.decode("utf-8")
    token = str(token)
    return token


def bienvenida():
    """Interfaz de bienvenida"""
    print("Bienvenido al programa")
    print("Pulse 1 para registrar")
    print("Pulse 2 para iniciar sesion")
    print("Pulse 3 para cerrar el programa \n")
    
    res = input("")
    if res != "1" and res != "2" and res != "3":
        bienvenida()
    if res == "1": 
        registro()
    if res == "2": 
        inicio()
    if res == "3":        
        sys.exit("PROGRAMA FINALIZADO") 
       

def is_prime(n):
  """Nos dirá si es primo"""
  for i in range(2, n):
    if (n%i) == 0:
      return False
  return True
 

def generatePublic():
    """Esta función generará una clave privada al azar"""
    while True:
        a = random.randrange(40000,90000)
        if is_prime(a): 
            return a
def mandar(usuario, usuario2):
    """Función para mandar mensajes simétricos"""
    store = JsonStore()
    mensaje = input("Introduce el mensaje \n")
    mensaje = bytes(mensaje, 'utf-8')
    token = f.encrypt(mensaje)

    token = token.decode("utf-8")
    token = str(token)
    
    
    store.load()
    lista = store._data_list
    for n in lista:
        if n["_Usuario__usuario"] == usuario: 
            n["mensajes"].append(token)
    
    store._data_list = lista 
    store.save()
    iniciado(usuario2)


def ver(usuario):
   """Función que ve los mensajes"""
   item = JsonStore().find_item(usuario, "_Usuario__usuario")
   if item == None:
       raise TypeError("Ha sucedido un error")
   i = 1
   if len(item["mensajes"]) == 0:
       print("NO HAY MENSAJES")
   for n in item["mensajes"]:
       
       token = n.encode("utf-8")
      
       mensaje = f.decrypt(token)
       mensaje = mensaje.decode("utf-8")
       print("MENSAJE" + str(i) + ": \n", mensaje)
       i += 1
   iniciado(usuario)
def registro():
    """Función que registra a un usuario"""
    usuario = input("Cual es el nombre del usuario: \n")
    usuario = hashlib.sha256(usuario.encode()).hexdigest()
    item = JsonStore().find_item(usuario,"_Usuario__usuario")
    
    if item != None: 
        print("El usario ya esta registrado \n")
        bienvenida()
    contraseña = input("Cual es el la contraseña: \n")
    
    chequeo = checkPass(contraseña)
    # Creamos las claves del usuario
    random_generator=Crypto.Random.new().read
    private_key=RSA.generate(1024, random_generator)
    public_key=private_key.publickey()

    private_key = private_key.exportKey(format= 'DER')
    public_key = public_key.exportKey(format='DER')
    private_key = binascii.hexlify(private_key).decode('utf8')
    public_key = binascii.hexlify(public_key).decode('utf8')
    # Si la contraseña no es válida volvemos a la interfaz de inicio
    if not chequeo: 
        bienvenida()
    contraseña = hashlib.sha256(contraseña.encode()).hexdigest()
    
   
   
    a = JsonStore()
    # Usarios creados con los certificados (los 3 primeros)
    if len(a._data_list) == 0:
        b = JsonStore("3users")
        b = b._data_list
        b = b[0]
        clase = Usuario(usuario, contraseña, private_key, public_key, b["n"], b["e"], b["d"])
        JsonStore().add_item(clase)
    elif len(a._data_list) == 1:
        b = JsonStore("3users")
        b = b._data_list
        b = b[1]
        clase = Usuario(usuario, contraseña, private_key, public_key, b["n"], b["e"], b["d"])
        JsonStore().add_item(clase)
    elif len(a._data_list) == 2:
        b = JsonStore("3users")
        b = b._data_list
        b = b[2]
        clase = Usuario(usuario, contraseña, private_key, public_key, b["n"], b["e"], b["d"])
        JsonStore().add_item(clase)
    else:
        clase = Usuario(usuario, contraseña, private_key, public_key)
        JsonStore().add_item(clase)
    print("¡Usuario registrado!\n")
    bienvenida()
    
def inicio():
    """Funcion para comprobar si la contraseña es correcta"""
    a = random.random()
    if a > .5: 
        # Generamos números al azar
        b = random.randrange(1, 20)
        c = random.randrange(1, 20)
        print("Control de autrenticación\n")
        print("¿Cuánto es " + str(b) + " + " + str(c) + "?\n")
        intentos = 3
        sol = False
        while not sol:
            d = input("")
            
            try:
                int(d)
            except: 
                print("Cool down de 10 segundos...")
                time.sleep(10)
                bienvenida()
            if int(d) != b + c:
                intentos -= 1
                print("Proceso fallido, tiene: " + str(intentos) + " intentos")
                
            if int(d) == b + c:
                sol = True
            if intentos == 0: 
                print("Cool down de 10 segundos...")
                time.sleep(10)
                bienvenida()
            
    usuario = input("usuario: \n")
    usuario = hashlib.sha256(usuario.encode()).hexdigest()
    contraseña = input("contraseña: \n")
    
    item = JsonStore().find_item(usuario, "_Usuario__usuario")
    # Miramos si existe el usuario
    if item == None: 
        print("El usario no esta registrado\n")
        bienvenida()
    contraseña = hashlib.sha256(contraseña.encode()).hexdigest()
    # Si esta bien iniciamos sesión
    if (item["_Usuario__password"] == contraseña): 
        iniciado(usuario)
    else:
        print("Incio fallido\n")
        bienvenida()


def checkPass(password):
    """Función que comprubeba que la longitud de las contraseñas es de 8 dígitos
    ,contiene una mayúscula dos números y un caracter especial"""
    especiales = [64, 43, 47, 44, 33, 58, 59, 60, 61, 62, 63, 123, 124, 125, 126]
    especiales_ = 0
    numeros = 0
    if len(password) < 8:
        print("La contraseña debe contener mas de 8 digitos\n")
        return False
    mayus = 0
    for n in password: 
        if ord(n) > 64 and ord(n) < 91:
            mayus+= 1
        if ord(n) in especiales:
            especiales_ +=1 
        try: 
            int(n)
            numeros += 1
        except:
            pass

    if mayus == 0:
        print("Debe contener una mayúscula\n")
        return False
    if especiales_ == 0:
        print("Debe contener un caracter especial\n")
        return False
    if numeros <= 1:
        print("Debe contener al menos 2 números\n")
        return False
    return True
def iniciado(usuario): 
    """Función cuando la sesión está iniciada"""
    print("\nPulse 1 para ver mis mensajes anónimos")
    print("Pulse 2 para mandar un mensaje anónimo")
    print("Pulse 3 para mandar un mensaje firmado")
    print("Pulse 4 para ver los mensajes firmados")
    print("Pulse 5 para cerrar sesión")
    print("Pulse 6 para cerrar el programa \n")
    usuario2 = usuario
    res = input("")
    options = ["1", "2", "3", "4", "5", "6"]
    if res not in options:
        iniciado(usuario)
    if res == "1": 
        ver(usuario)
    if res == "2": 
        usuario = input ("¿A que usuario se lo quieres mandar? \n")
        usuario = hashlib.sha256(usuario.encode()).hexdigest()
        item = JsonStore().find_item(usuario, "_Usuario__usuario")
        
        if item == None: 
            print("El usario no existe")
            iniciado(usuario2)
        mandar(usuario, usuario2)
    if res == "5":        
        bienvenida()
    if res == "6":        
        sys.exit("PROGRAMA FINALIZADO")
    if res == "3": 
        usuario = input ("¿A que usuario se lo quieres mandar? \n")
        usuario = hashlib.sha256(usuario.encode()).hexdigest()
        item = JsonStore().find_item(usuario, "_Usuario__usuario")
        
        
        if item == None: 
            print("El usario no existe")
            iniciado(usuario2)
        asimetrico(usuario2, usuario)
    if res == "4": 
        
        ver_asimetrico(usuario2)
def ver_asimetrico(usuario):
    """Función que ve los mensajes asimétricos"""
    store = JsonStore()
    store.load()
    mensajes = []
    copia = usuario
    for n in store._data_list: 
                   
        if n["_Usuario__usuario"] == usuario:
            private_key = n["private"]
            mensajes = n["mensajes_asimetrticos"]
            firma = n["firma"]
    if len(mensajes) == 0: 
        print("No hay mensajes")
        iniciado(usuario)
    private_key=RSA.importKey(binascii.unhexlify(private_key))
    contador = 0
   
    for n in mensajes: 
            
            print("\nMensaje " + str(contador + 1) +" \n")
            #Descriptamos el mensaje
            n = n.encode('cp437')
            cipher=PKCS1_OAEP.new(private_key)
            mensaje=cipher.decrypt(n)
            mensaje = mensaje.decode('cp437')
            print(mensaje + "\n")
            
            
            # Firma y usuario emisor
            usuario = firma[contador][1]
            usuario = (decrypt(usuario))
            firma_ = firma[contador][0]
            
            userhash =  hashlib.sha256(usuario.encode()).hexdigest()
            # Pasamos el mensaje a hash, ya que la firma tambien viene en hash
            # Luego a codigo ascii tal y como se hizo en la firma
            message = hashlib.sha512(mensaje.encode()).hexdigest()
            message = int(_ascii(message))
            cont = False
            print("Comienza la comprobación de la firma...")
            time.sleep(2)
            cont = 0
            
            for h in store._data_list: 
                               
                if h["_Usuario__usuario"] == userhash:
                    cont +=1 
                    e = h["e"]
                    n = h["n"]
                    n = int(decrypt(n))
                    e = int(decrypt(e))
            # La variable cont nos sirve para saber si no se ha encontrado un usuario
            if cont > 0:
                print("Clave púlica obtenida")
                time.sleep(2)
                """Desciframos con la pública y comprobamos que es igual que message
                , es decir el mensaje que se nos había mandado"""
                print("Chequeo finalizado")
                if pow(firma_ , e, n) == message:
                                       
                   print("El mensaje nos lo ha enviado " + usuario)
                else:
                     print("No se ha completado correctamente el proceso de firma, el emisor no es: ", usuario)
            else:
                 print("No se ha completado correctamente el proceso de firma, el emisor no es: ", usuario)
            contador += 1
    
    iniciado(copia)
def _ascii(cadena): 
    """Función que convierte un str en código ascii"""
    a = ""
    for n in cadena: 
        n = ord(n)
        a = a + str(n)
    return a


def asimetrico(emisor,receptor): 
    """Función que manda mensaje con encriptación asimétrica"""
    store = JsonStore()
    store.load()
    n = None
    d = None

    for h in store._data_list: 
        if h["_Usuario__usuario"] == receptor: 
            # Publica para mandar mensaje
            public = h["publica"]
        if h["_Usuario__usuario"] == emisor: 
            # Claves para firma digital
            n = h["n"]
            d = h["d"]
    n = int(decrypt(n))
    d = int(decrypt(d))
    print("¿Cúal es el mensaje que desea enviar?")
    message_ = input("")
    print("¿Cúal es su usuario?")
    pseudónimo = input("")
    # Encriptamos
    message=message_.encode()
    public_key=RSA.importKey(binascii.unhexlify(public))
    cipher = PKCS1_OAEP.new(public_key)
    encriptado=cipher.encrypt(message)
    encriptado1 = encriptado.decode('cp437')
    
    
    
    # Firma digital
    message = hashlib.sha512(message_.encode()).hexdigest()
    message = int(_ascii(message))
    signature1 = pow(message,d,n)
    for n in store._data_list:
        if n["_Usuario__usuario"] == receptor:
            n["mensajes_asimetrticos"].append(encriptado1)
            pseudónimo = encrypt(pseudónimo)
            #Enviamos la firma y el supuesto emisor
            n["firma"].append((signature1, pseudónimo))
    store.save()
    iniciado(emisor)


a = JsonStore("key")

a.load()
# Miramos si hay una clave ya creada para el simétrico

if len(a._data_list) == 0:
    key = Fernet.generate_key()
    key = key.decode("utf-8")

    key_ = Key(str(key))
    a.add_item(key_)
else:
    #Si no existe la creamos
    a = JsonStore("key")
    a.load()
    dic = a._data_list
    dic = dic[0]
    key = dic["_Key__key"]
   
    key = key.encode("utf-8")
f = Fernet(key)        


# Creamos el fichero con los 3 usuarios de los certificados
a = JsonStore("3users")
if len(a._data_list) == 0:
    with open("certificados/A/Akey.pem", "rb") as file:
        data = file.read()
    
    keyPair = RSA.import_key(data, "prueba")
    
    n = encrypt(keyPair.n)
    e = encrypt(keyPair.e)
    d = encrypt(keyPair.d)
    
    b = ned(n, e, d)
    a.add_item(b)
    with open("certificados/B/Bkey.pem","rb") as file:
         data = file.read()
      
    keyPair = RSA.import_key(data, "prueba")
    n = encrypt(keyPair.n)
    e = encrypt(keyPair.e)
    d = encrypt(keyPair.d)
    b = ned(n,e,d)
    a.add_item(b)
    
    with open("certificados/C/Ckey.pem", "rb") as file:
         data = file.read()
      
    keyPair = RSA.import_key(data, "prueba")
    n = encrypt(keyPair.n)
    e = encrypt(keyPair.e)
    d = encrypt(keyPair.d)
    b = ned(n,e,d)
    a.add_item(b)

bienvenida()






    
    


