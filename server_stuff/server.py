import socket            
import secrets
import hashlib
import time
import threading
import os
from encryption import DH,AES
class connection():
    def __init__(self):
        #network things
        self.s = socket.socket()
        self.PORT = 12345
        #codes
        self.FAILURE = "400"
        self.AUTHERROR = "401"
        self.NOTALLOWED = "500"
        self.GOAHEAD = "200"
        #files
        self.AUTHCODES = "active_auth_codes.txt"
        self.USERACCOUNTS = "user_accounts.txt"
        self.MANIFEST = "manifest.txt"
        #commands
        self.REFRESHAUTH = "rac"
        self.CREATEACCOUNT = "ca"
        self.UPLOADDATA = "ud"
        self.CHECKAUTH_COMMAND = "cac"
        #other
        self.LARGESIZE = 20000
        self.KEYTIMEOUT = 3600 #seconds, one hour
    def start(self)->None:
        print("online")
        self.s.bind(("",self.PORT))
        self.s.listen(5)
        while True:
            c,addr = self.s.accept()
            
            print("got connection from",addr)
            
            threading.Thread(target=self.handler,args=[c]).start()

    def handler(self,c)->None:
        self._send_message(c,self.GOAHEAD,setup=True)
        generating_key = True
        if generating_key:
            diffie = DH()
            modulus = int(self._recieve_message(c,setup=True))
            self._send_message(c," ",setup=True)
            base = int(self._recieve_message(c,setup=True))
            self._send_message(c," ",setup=True)
            bg = int(self._recieve_message(c,setup=True))
            dhkey = diffie.generate_key()
            ag = diffie.equation(base,dhkey,modulus)
            self._send_message(c,ag,setup=True)
            a = AES("")
            self.key = a.produce_key(diffie.equation(bg,dhkey,modulus))
            print(self.key)
        command = self._recieve_message(c)
        if not command:
            return
        command = command.strip()
        match command:
            case self.REFRESHAUTH:
                self.refresh_token(c)
            case self.CREATEACCOUNT:
                self.create_account(c)
            case self.UPLOADDATA:
                self.upload_data(c)
            case self.CHECKAUTH_COMMAND:
                self.checking(c)
            case _:
                print("command",command)
                self._send_message(c,self.FAILURE)
                c.close()
        print(command)

    def _send_message(self,sock,message,setup=False)->None:
        if setup:
            sock.sendall(str(message).encode())
        else:
            a = AES(message)
            encrypted_message = a.encrypt(self.key)
            sock.sendall(encrypted_message.encode())
        print("sent : ",message)
    def _recieve_message(self,sock,setup=False,size=1024)-> str:
        try:
            data = sock.recv(size)
            data = data.decode()
            if setup:
                print("recieved :",data)
                return data.strip()
            else:
                a = AES(data)
                message = a.decrypt(self.key)
                print("recieved :",message)
                return message.strip()
        except ConnectionResetError:
            return False
    
    def refresh_token(self,user):
        self._send_message(user,self.GOAHEAD)
        refresh_code = self._recieve_message(user,size=self.LARGESIZE)
        if not refresh_code:
            return
        file = open(self.USERACCOUNTS,"r")
        codes = file.read()
        file.close()
        codes = codes.split("\n")
        passed = False
        for code in codes:
            code = code.split(",")
            acode = code[1]
            if acode == refresh_code:
                person = code[0]
                passed = True

        if passed:
            auth_code = secrets.token_hex(32)
            self._send_message(user,auth_code)
            user.close()
            current_time = time.time()
            file = open(self.AUTHCODES,"a")
            addition = f"{person},{auth_code},{current_time}\n"
            file.write(addition)
            file.close()
        else:
            self._send_message(user,self.AUTHERROR)
            user.close()

    def check_auth(self,auth_code):
        file = open(self.AUTHCODES,"r")
        content = file.read()
        file.close()
        content = content.split("\n")
        for line in content:
            if line != "":
                line = line.split(",")
                check = line[1]
                if auth_code == check:
                    time_check = line[2]
                    current_time = time.time()
                    time_check = float(time_check)
                    if (current_time - time_check) < self.KEYTIMEOUT:
                        return line[0]
                
        return False
    def clear_codes(self,file_name,time_limit):
        file = open(file_name,"r")
        content = file.read()
        file.close()
        content = content.split("\n")
        for line in content:
            allowed = True
            formated_line = line.split(",")
            if "," not in line:
                content.remove(line)
            try:
                time_check = formated_line[2]
                time_check = float(time_check)
            except IndexError:
                allowed = False
                None
            current_time = time.time()
            if allowed:
                if (current_time - time_check) > time_limit:
                    content.remove(line)

        final = ""
        for line in content:
            final += line
            final += "\n"
        file = open(self.AUTHCODES,"w")
        file.write(final)
        file.close()

    def upload_data(self,user):
        self._send_message(user,self.GOAHEAD)

        auth = self._recieve_message(user,size=self.LARGESIZE)
        username = self.check_auth(auth)
        if not username:
            self._send_message(user,self.AUTHERROR)
            return
        self._send_message(user,self.GOAHEAD)
        size = int(self._recieve_message(user))
        self._send_message(user,self.GOAHEAD)
        print("size",size)
        data = self._recieve_message(user,size=size)
        os.chdir("data")#consider using relative path instead of this awfullness
        os.chdir(username)#although because of the miracle that is threading this could work
        files = os.listdir()

        while True:
            name = secrets.token_hex(16)
            if name not in files:
                break
        file = open(name,"w")
        file.write(data)
        file.close()
        self._send_message(user,self.GOAHEAD)
        self._recieve_message(user)
        self._send_message(user,name)
        current_time = time.time()
        file = open(self.MANIFEST,"a")
        entry = f"{name},{current_time}\n"
        file.write(entry)
        file.close()
        return True

    def monitor_auth(self,timer,seperate=False):
        if not seperate:
            threading.Thread(target=self.monitor_auth,args=[timer,True]).start()
            return
        while True:
            self.clear_codes(self.AUTHCODES,timer)
            time.sleep(600)

    def checking(self,user):
        self._send_message(user,self.GOAHEAD)
        code = self._recieve_message(user,size=self.LARGESIZE)
        if self.check_auth(code):
            self._send_message(user,self.GOAHEAD)
            return
        self._send_message(user,self.AUTHERROR)
        user.close()
        
    def create_account(self,user):
        self._send_message(user,self.GOAHEAD)
        counter = 0 
        while True:
            counter += 1
            username = self._recieve_message(user)
            password = self._recieve_message(user,size=self.LARGESIZE)
            self._send_message(user,username)
            self._send_message(user,password)
            check = self._recieve_message(user)
            if check == self.GOAHEAD:
                break
            if counter > 3:
                user.close()
                return False
        file = open(self.USERACCOUNTS,"r")
        content = file.read()
        file.close()
        content = content.split("\n")
        for line in content:
            line = line.split(",")
            name = line[0]
            if name == username:
                self._send_message(self.NOTALLOWED)
                return
        self._send_message(user,self.GOAHEAD)
        enter = f"\n{username},{password}"
        file = open(self.USERACCOUNTS,"a")
        file.write(enter)
        file.close()
        os.chdir("data")
        os.mkdir(username)
        os.chdir(username)
        file = open(self.MANIFEST,"w")
        file.close()
        return True
            
if __name__ == "__main__":
    a = connection()
    a.monitor_auth(3600)
    a.start()

