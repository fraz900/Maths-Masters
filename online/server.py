import socket            
import secrets
import hashlib
import time
import threading
import os
import sys
import time
from encryption import DH,AES
class connection():
    def __init__(self):
        #network things
        self.s = socket.socket()
        self.PORT = 12345
        #codes
        self.FAILURE = "400"
        self.AUTHERROR = "401"
        self.NOTFOUND = "404"
        self.NOTALLOWED = "500"
        self.GOAHEAD = "200"
        self.INVALID = "501"
        self.MATCHMAKINGERROR = "100"
        #files
        self.AUTHCODES = "active_auth_codes.txt"
        self.USERACCOUNTS = "user_accounts.txt"
        self.MANIFEST = "manifest.txt"
        self.LFG = "lfg.txt"
        self.ACTIVEGAMES = "games.txt"
        #commands
        self.REFRESHAUTH = "rac"
        self.CREATEACCOUNT = "ca"
        self.UPLOADDATA = "ud"
        self.UPDATEDATA = "upd"
        self.DELETEDATA = "dd"
        self.VIEWDATA = "vd"
        self.SHARE = "sd"
        self.CHECKLOGIN = "cl"
        self.CHECKAUTH_COMMAND = "cac"
        self.GETOWNERSHIP = "go"
        self.MATCHMAKING = "mm"
        #other
        self.LARGESIZE = 20000
        self.KEYTIMEOUT = 3600 #seconds, one hour
        self.TIMEOUT = 10
    def start(self)->None:
        print("online")
        self.s = socket.socket()
        self.s.bind(("",self.PORT))
        self.s.listen(5)
        while True:
            c,addr = self.s.accept()
            c.settimeout(self.TIMEOUT)
            print("got connection from",addr)
            
            threading.Thread(target=self.handler,args=[c,addr]).start()

    def handler(self,c,ip)->None:
        os.chdir(os.path.split(__file__)[0])
        self._send_message(c,self.GOAHEAD,setup=True)
        generating_key = True
        if generating_key:
            diffie = DH()
            try:
                modulus = int(self._recieve_message(c,setup=True))
            except:
                self.log(ip,"ping")
                c.close()
                return
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
                self.user_auth_checking(c)
            case self.UPDATEDATA:
                self.update(c)
            case self.DELETEDATA:
                self.delete(c)
            case self.VIEWDATA:
                self.view(c)
            case self.SHARE:
                self.share(c)
            case self.GETOWNERSHIP:
                self.get_ownership(c)
            case self.CHECKLOGIN:
                self.login(c,ip)
            case self.MATCHMAKING:
                self.matchmaking(c)
            case _:
                print("command",command)
                self._send_message(c,self.FAILURE)
                c.close()
        self.log(ip,command)
        print(command)
    def log(self,ip,command):
        current_time = time.time()
        os.chdir(os.path.split(__file__)[0])
        entry = f"{ip},{command},{current_time}\n"
        file = open("log.txt","a")
        file.write(entry)
        file.close()
        return True
    def _send_message(self,sock,message,setup=False)->None:
        message = str(message)
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
            sys.exit()
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

    def _authenticate(self,user):
        self._send_message(user,self.GOAHEAD)
        auth = self._recieve_message(user,size=self.LARGESIZE)
        username = self.check_auth(auth)
        if not username:
            self._send_message(user,self.AUTHERROR)
            return False
        self._send_message(user,self.GOAHEAD)
        return username
    
    def upload_data(self,user):
        username = self._authenticate(user)
        if not username:
            user.close()
            return False
        shared_state = self._recieve_message(user)
        shared = False
        if shared_state == "shared":
            shared = True
        self._send_message(user,self.GOAHEAD)
        size = int(self._recieve_message(user))
        self._send_message(user,self.GOAHEAD)
        
        data = self._recieve_message(user,size=size)
        os.chdir("data")
        if not shared:
            os.chdir(username)
            files = os.listdir()

            while True:
                name = secrets.token_hex(16)
                if name not in files:
                    break
            file = open(name,"w")
            file.write(data)
            file.close()
        else:
            os.chdir("shared")
            files = os.listdir()
            while True:
                name = secrets.token_hex(16)
                if name not in files:
                    break
            file = open(name,"w")
            file.write(data)
            file.close()
            namer = f"{name} ownership"
            file = open(namer,"w")
            entry = f"{username}\n"
            file.write(entry)
            file.close()
        os.chdir(os.path.split(__file__)[0])
        os.chdir("data")
        os.chdir(username)
        self._send_message(user,self.GOAHEAD)
        self._recieve_message(user)
        self._send_message(user,name)
        current_time = time.time()
        file = open(self.MANIFEST,"a")
        entry = f"{name},{current_time},{shared_state}\n"
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

    def user_auth_checking(self,user):
        self._send_message(user,self.GOAHEAD)
        code = self._recieve_message(user,size=self.LARGESIZE)
        if self.check_auth(code):
            self._send_message(user,self.GOAHEAD)
            return
        self._send_message(user,self.AUTHERROR)
        user.close()

    def update(self,user):
        username = self._authenticate(user)
        if not username:
            user.close()
            return False
        filename = self._recieve_message(user,size=self.LARGESIZE)
        os.chdir("data")
        os.chdir(username)
        file = open(self.MANIFEST,"r")
        content = file.read()
        file.close()
        if filename not in content:
            self._send_message(user,self.NOTFOUND)
            user.close()
            return False
        self._send_message(user,self.GOAHEAD)
        change = self._recieve_message(user)
        content = content.split("\n")
        for line in content:
            if filename in line:
                line = line.split(",")
                shared_check = line[2]
                shared = False
                if shared_check == "shared":
                    shared = True

        if shared:
            os.chdir(os.path.split(__file__)[0])
            os.chdir("data")
            os.chdir("shared")
        file = open(filename,"w")#if two users try to update at same time?
        file.write(change)
        file.close()
        self._send_message(user,self.GOAHEAD)
        user.close()
                

    def delete(self,user):
        username = self._authenticate(user)
        if not username:
            user.close()
            return False
        filename = self._recieve_message(user,size=self.LARGESIZE)
        os.chdir("data")
        os.chdir(username)
        file = open(self.MANIFEST,"r")
        content = file.read()
        file.close()
        if filename not in content:
            self._send_message(user,self.NOTFOUND)
            user.close()
            return False
        content = content.split("\n")
        done = False
        for line in content:
            line = line.split(",")
            if line[0] == filename:
                if line[2] == "shared":
                    done = True
                    os.chdir(os.path.split(__file__)[0])
                    os.chdir("data")
                    os.chdir("shared")
                    namer = f"{filename} ownership"
                    file = open(namer,"r")
                    stuff = file.read()
                    file.close()
                    final = ""
                    stuff = stuff.split("\n")
                    for sline in stuff:
                        if sline != username:
                            final += sline + "\n"
                    if final == "":
                        os.remove(filename)
                        os.remove(namer)
                    else:
                        file = open(namer,"w")
                        file.write(final)
                        file.close()
        os.chdir(os.path.split(__file__)[0])
        os.chdir("data")
        os.chdir(username)
        if not done:
            os.remove(filename)
        self._send_message(user,self.GOAHEAD)
        user.close()
        file = open(self.MANIFEST,"r")
        content = file.read()
        file.close()
        new = []
        content = content.split("\n")
        for line in content:
            if filename not in line:
                new.append(line)
        final = ""
        for line in new:
            final += line + "\n"
        file = open(self.MANIFEST,"w")
        file.write(final)
        file.close()
        return True
    def view(self,user):
        username = self._authenticate(user)
        if not username:
            user.close()
            return False
        filename = self._recieve_message(user,size=self.LARGESIZE)
        os.chdir("data")
        os.chdir(username)
        file = open(self.MANIFEST,"r")
        content = file.read()
        file.close()
        if filename not in content:
            self._send_message(user,self.NOTFOUND)
            user.close()
            return False

        content = content.split("\n")
        for line in content:
            if filename in line:
                line = line.split(",")
                shared_check = line[2]
                shared = False
                if shared_check == "shared":
                    shared = True

        if shared:
            os.chdir(os.path.split(__file__)[0])
            os.chdir("data")
            os.chdir("shared")
        file = open(filename,"r")#what if two users try and view at the same time?
        content = file.read()
        file.close()
        self._send_message(user,content)
        user.close()
    def login(self,user,ip):
        self._send_message(user,self.GOAHEAD)
        username = self._recieve_message(user)
        file = open(self.USERACCOUNTS,"r")
        content = file.read()
        content = content.split("\n")
        found = False
        for line in content:
            check = line.split(",")
            if check[0] == username:
                found = True
                spassword = check[1]
        if not found:
            self._send_message(user,self.NOTFOUND)
            self.log(ip,f"login {username} not found")
            user.close()
            return False
        self._send_message(user,self.GOAHEAD)
        password = self._recieve_message(user,size=self.LARGESIZE)
        if password == spassword:
            self._send_message(user,self.GOAHEAD)
            self.log(ip,f"login {username} correct")
            user.close()
            return True
        self._send_message(user,self.AUTHERROR)
        self.log(ip,f"login {username} incorrect")
        user.close()
        return False
    def share(self,user):
        username = self._authenticate(user)
        if not username:
            user.close()
            return False
        user_to_share = self._recieve_message(user,size=self.LARGESIZE)
        file = open(self.USERACCOUNTS,"r")
        content = file.read()
        content = content.split("\n")
        found = False
        for line in content:
            check = line.split(",")
            if check[0] == user_to_share:
                found = True
        if not found:
            self._send_message(user,self.NOTFOUND)
            user.close()
            return False
        self._send_message(user,self.GOAHEAD)
        filename = self._recieve_message(user,size=self.LARGESIZE)
        os.chdir("data")
        os.chdir(username)
        file = open(self.MANIFEST,"r")
        content = file.read()
        file.close()
        content = content.split("\n")
        final = ""
        found = False
        x = 0
        for line in content:
            split_line = line.split(",")
            if split_line[0] == filename:
                found = True
                if split_line[2] == "singular":
                    split_line[2] = "shared"
                    new = ",".join(split_line)
                    content[x]  = new
                    file = open(filename,"r")
                    stuff = file.read()
                    file.close()
                    os.remove(filename)
                    os.chdir(os.path.split(__file__)[0])
                    os.chdir("data")
                    os.chdir("shared")
                    file = open(filename,"w")
                    file.write(stuff)
                    file.close()
                    namer = f"{filename} ownership"
                    file = open(namer,"w")
                    entry = f"{username}\n{user_to_share}\n"
                    file.write(entry)
                    file.close()
                else:
                    os.chdir(os.path.split(__file__)[0])
                    os.chdir("data")
                    os.chdir("shared")
                    entry = f"{user_to_share}\n"
                    fname = f"{filename} ownership"
                    file = open(fname,"a")
                    file.write(entry)
                    file.close()
            x += 1
        if not found:
            self._send_message(user,self.NOTFOUND)
            user.close()
            return False
        os.chdir(os.path.split(__file__)[0])
        os.chdir("data")
        os.chdir(username)
        entry = "\n".join(content)
        file = open(self.MANIFEST,"w")
        file.write(entry)
        file.close()
        os.chdir(os.path.split(__file__)[0])
        os.chdir("data")
        os.chdir(user_to_share)
        current_time = time.time()
        file = open(self.MANIFEST,"a")
        entry = f"{filename},{current_time},shared\n"
        file.write(entry)
        file.close()
        self._send_message(user,self.GOAHEAD)
        user.close()
        return True
        
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
    def get_ownership(self,user):
        username = self._authenticate(user)
        if not username:
            user.close()
            return False
        filename = self._recieve_message(user,size=self.LARGESIZE)
        os.chdir("data")
        os.chdir(username)
        file = open(self.MANIFEST,"r")
        content = file.read()
        content = content.split("\n")
        found = False
        for line in content:
            split_line = line.split(",")
            if split_line[0] == filename:
                found = True
                if split_line[2] != "shared":
                    self._send_message(user,self.INVALID)
                    user.close()
                    return False
        if not found:
            self._send_message(user,self.NOTFOUND)
            user.close()
            return False
        new_name = f"{filename} ownership"
        os.chdir(os.path.split(__file__)[0])
        os.chdir("data")
        os.chdir("shared")
        file = open(new_name,"r")
        stuff = file.read()
        file.close()
        a = AES(stuff)
        new_data = a.encrypt(self.key)
        size = self._size(new_data)
        size *= 1.2
        size = int(size)

        self._send_message(user,self.GOAHEAD)
        self._recieve_message(user)
        self._send_message(user,size)
        self._recieve_message(user)
        self._send_message(user,stuff)
        user.close()
        return True

    def _size(self,s)->int:
        return len(s.encode('utf-8')) 

    def matchmaking(self,user):
        username = self._authenticate(user)
        if not username:
            user.close()
            return False
        self._recieve_message(user)
        self._send_message(user,self.GOAHEAD)
        self._recieve_message(user)

        #consider level comparison for better matchmaking

        file = open(self.LFG,"r")
        content = file.read()
        file.close()
        content = content.split("\n")
        if len(content) == 0:
            file = open(self.LFG,"a")
            entry = f"{username}\n"
            file.write(entry)
            file.close()
            counter = 0
            while True:
                counter += 1
                if counter >=300:
                    #matchmaking error

                #give info and start game
                time.sleep(1)
        else:
            opponent = content[0]
            content = content.pop(0)
            entry = "\n".join(content)
            file = open(self.LFG,w)
            file.write(entry)
            file.close()
            namer = f"{username},{opponent}"
            entry = namer + "\n"
            file = open(self.ACTIVEGAMES,"a")
            file.write(entry)
            file.close()
            parent = os.getcwd()
            next_level = os.path.join(parent,"games")
            final_level = os.path.join(next_level,namer)
            os.mkdir(final_level)
            score_path = os.path.join(final_level,f"{username} score.txt")
            file = open(score_path,"w")
            file.write("0")
            file.close()
            self._send_message(self.s,self.GOAHEAD)
            self._recieve_message(self.s)
            self._send_messge(self.s,namer)
            
            
        #log request
        #hold request for 5 minutes
        #if matching request comes link em
        #if not return matchmaking error
            
if __name__ == "__main__":
    a = connection()
    a.monitor_auth(3600)
    a.start()

