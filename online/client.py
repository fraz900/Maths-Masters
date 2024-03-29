import socket
import hashlib
import time
from threading import Thread
try:
    from online.encryption import DH,AES
except:
    from encryption import DH,AES
class connection():
    def __init__(self,IP="127.0.0.1",PORT=12345,debug=False):
        self.DEBUG = debug
        #network things
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SERVER_IP = IP
        self.PORT = PORT
        #commands
        self.REFRESHAUTH_COMMAND = "rac"
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
        self.CHECKMATCHMAKING = "cmm"
        self.CHECKSCORES = "cs"
        self.STARTGAME = "sc"
        self.CHANGESCORES = "css"
        self.GENERATEKEY = "gk"
        #responses
        self.GOAHEAD = "200"
        self.WARNINGS = {"400":"client error, incorrect command","401":"authentication error, failure to authenticate","404":"resource not found","500":"Data not allowed","501":"invalid resource"}
        self.MATCHMAKINGERROR = "100"
        #other
        try:
            file = open("details.txt","r")
            content = file.read()
            file.close()
            content = content.split(",")
            self.REFRESH_CODE = content[1]
            self.USER_NAME = content[0]
        except:
            self.REFRESH_CODE = None
            self.USER_NAME = None
        self.KEYTIMEOUT = 3600 #seconds, one hour
        self.AUTHCODE = None
        self.LARGESIZE = 20000
        self.UPLOADS = "uploads.txt"

    def print1(self,message):
        if self.DEBUG:
            print(message)
    def _send_message(self,sock,message,setup=False):
        message = str(message)
        self.print1(f"sent : {message}")
        if setup:
            sock.sendall(str(message).encode())
        else:
            a = AES(message)
            encrypted_message = a.encrypt(self.key)
            self.print1(self._size(encrypted_message))
            sock.sendall(encrypted_message.encode())
            
    def _recieve_message(self,size=1024,setup=False):
        data = self.s.recv(size)
        data = data.decode()
        if setup:
            self.print1(f"recieved : {data}")
            return data.strip()
        else:
            a = AES(data)
            message = a.decrypt(self.key)
            self.print1(f"recieved : {message}")
            return message.strip()

    def _error_handling(self,error):
        error = str(error)
        error = error.strip()
        try:
            error = self.WARNINGS[error]
        except KeyError:
            error = "UNKNOWN ERROR"
        raise Exception(error)
    def _size(self,s)->int:
        return len(s.encode('utf-8'))
    def _initiate_connection(self,generate_key=True):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.SERVER_IP,self.PORT))
        data = self._recieve_message(setup=True)
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False

        if generate_key:
            self._send_message(self.s,self.GENERATEKEY,setup=True)
            diffie = DH()
            dhKey = diffie.generate_key()
            modulus = diffie.generate_prime()
            base = diffie.generate_base(modulus)
            ag = diffie.equation(base,dhKey,modulus)
            self._send_message(self.s,modulus,setup=True)
            self._recieve_message(setup=True)
            self._send_message(self.s,base,setup=True)
            self._recieve_message(setup=True)
            self._send_message(self.s,ag,setup=True)
            bg = int(self._recieve_message(setup=True))
            final = diffie.equation(bg,dhKey,modulus)
            a = AES("")
            self.key = a.produce_key(final)
        else:
            self._send_message(self.s,self.GOAHEAD,setup=True)
    def get_auth_token(self):
        current_time = time.time()
        try:
            file = open("code.txt","r")
            content = file.read()
            file.close()
            content = content.split(",")
            check_time = float(content[0])
            if (current_time-check_time) < self.KEYTIMEOUT:
                self.AUTHCODE = content[1]
                self._initiate_connection()
                self._send_message(self.s,self.CHECKAUTH_COMMAND)
                data = self._recieve_message()
                data = data.strip()
                if data != self.GOAHEAD:
                    self._error_handling(data)
                    return False
                self._send_message(self.s,self.AUTHCODE)
                data = self._recieve_message()
                self.s.close()
                if data.strip() == self.GOAHEAD:
                    return True
        except:
            None
                    
        commands = [self.REFRESHAUTH_COMMAND,self.REFRESH_CODE]
        self._initiate_connection()
        self._send_message(self.s,self.REFRESHAUTH_COMMAND)
        data = self._recieve_message()
        data = data.strip()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False
        self._send_message(self.s,self.REFRESH_CODE)
        data = self._recieve_message(size=self.LARGESIZE)
        data = data.strip()
        try:
            test = self.WARNINGS[data]
            self._error_handling(data)
        except KeyError:
            self.AUTHCODE = data
            file = open("code.txt","w")
            entry = f"{current_time},{data}"
            file.write(entry)
            file.close()
            self.s.close()
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            return True
        
    def create_account(self,username,password):
        hasher = hashlib.sha256()
        hasher.update(password.encode())
        password = hasher.hexdigest()
        self._initiate_connection()
        self._send_message(self.s,self.CREATEACCOUNT)
        data = self._recieve_message()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False
        correct = False
        while not correct:
            self._send_message(self.s,username)
            self._send_message(self.s,password)
            user_test = self._recieve_message()
            password_test = self._recieve_message(size=self.LARGESIZE)
            if user_test == username and password_test == password:
                correct = True

        self._send_message(self.s,self.GOAHEAD)
        data = self._recieve_message()
        if data == self.GOAHEAD:
            entry = f"\n{username},{password}"
            file = open("details.txt","w")
            file.write(entry)
            file.close()
            self.REFRESH_CODE = password
            self.USER_NAME = username
            return True
        else:
            self._error_handling(data)

    def authenticated_start(self):
        if self.AUTHCODE == None:
            self.get_auth_token()
        auth = self.AUTHCODE
        
        self._initiate_connection()
        self._send_message(self.s,self.CHECKAUTH_COMMAND)
        data = self._recieve_message()
        data = data.strip()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False
        self._send_message(self.s,auth)
        data = self._recieve_message()
        self.s.close()
        if data.strip() == self.GOAHEAD:
            return auth
        else:
            self.get_auth_token()
            auth = self.AUTHCODE
            return auth
    
    def upload(self,data_to_send,name,shared=False,recurse=False):
        shared_state = "singular"
        if shared:
            shared_state = "shared"
        if self.AUTHCODE == None:
            self.get_auth_token()

        auth = self.AUTHCODE
        
        self._initiate_connection()
        self._send_message(self.s,self.UPLOADDATA)
        data = self._recieve_message()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False

        self._send_message(self.s,auth)
        confirm = self._recieve_message()
        if confirm != self.GOAHEAD:
            if recurse:
                self._error_handling(confirm)
                return False
            else:
                self.s.close()
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.AUTHCODE = None
                self.upload(data,name,recurse=True)
        self._send_message(self.s,shared_state)
        self._recieve_message()
        a = AES(data_to_send)
        new_data = a.encrypt(self.key)
        size = self._size(new_data)
        size *= 1.2
        size = int(size)
        self._send_message(self.s,size)
        self._recieve_message()
        self._send_message(self.s,data_to_send)
        check = self._recieve_message()
        if check != self.GOAHEAD:
            self._error_handling(check)
        self._send_message(self.s,self.GOAHEAD)
        
        namer = self._recieve_message(size=self.LARGESIZE)
        file = open(self.UPLOADS,"a")
        entry = f"\n{name},{namer}"
        file.write(entry)
        file.close()
        return namer

    def ping(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((self.SERVER_IP,self.PORT))
            data = self._recieve_message(setup=True)
            self.s.close()
            return True
        except:
            return False
    def login(self,username,password):
        hasher = hashlib.sha256()
        hasher.update(password.encode())
        password = hasher.hexdigest()
        self._initiate_connection()
        self._send_message(self.s,self.CHECKLOGIN)
        data = self._recieve_message()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False
        self._send_message(self.s,username)
        data = self._recieve_message()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False
        self._send_message(self.s,password)
        data = self._recieve_message()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False
        return True
    def update(self,filename,new):
        auth = self.authenticated_start()

        self._initiate_connection()
        self._send_message(self.s,self.UPDATEDATA)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        
        self._send_message(self.s,filename)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,new)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self.s.close()
        return True
        
    def delete(self,filename):
        auth = self.authenticated_start()

        self._initiate_connection()
        self._send_message(self.s,self.DELETEDATA)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        
        self._send_message(self.s,filename)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self.s.close()
        file = open(self.UPLOADS,"r")
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
        file = open(self.UPLOADS,"w")
        file.write(final)
        file.close()
        return True
    def view(self,filename):
        auth = self.authenticated_start()
        self._initiate_connection()
        self._send_message(self.s,self.VIEWDATA)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        
        self._send_message(self.s,filename)
        data = self._recieve_message(size=self.LARGESIZE)
        try:
            self.WARNINGS[data]
            self._error_handling(data)
            return
        except KeyError:
            None
        self.s.close()
        return data
    def share(self,filename,user_to_share):
        auth = self.authenticated_start()
        self._initiate_connection()
        self._send_message(self.s,self.SHARE)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,user_to_share)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,filename)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        return True

    def get_ownership(self,filename):
        auth = self.authenticated_start()
        self._initiate_connection()
        self._send_message(self.s,self.GETOWNERSHIP)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,filename)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,self.GOAHEAD)
        size = int(self._recieve_message())
        self._send_message(self.s,self.GOAHEAD)
        content = self._recieve_message(size=size)
        return content

    def matchmaking(self):#nt
        auth = self.authenticated_start()
        self._initiate_connection()
        self._send_message(self.s,self.MATCHMAKING)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,self.GOAHEAD)
        data = self._recieve_message()
        if data.strip() == self.MATCHMAKING:
            return 1
        elif data.strip() == "fg":
            return 2
        else:
            return 0
        #0 = error
        #1 = mathcmaking
        #2 = game found
    def check_matchmaking(self):#nt
        auth = self.authenticated_start()
        self._initiate_connection()
        self._send_message(self.s,self.CHECKMATCHMAKING)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        data = self._recieve_message()
        if data.strip() == self.MATCHMAKING:
            return False
        else:
            return data.strip() #match name
        
        
    def start_game(self,matchname):#nt
        auth = self.authenticated_start()
        self._initiate_connection()
        self._send_message(self.s,self.CHECKMATCHMAKING)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,auth)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        data = self._recieve_message()
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,match_name)
        data = self._receive_message()
        if data.strip() == self.GOAHEAD:
            self._send_message(self.s,self.GOAHEAD)
            code = self._receive_message(size=self.LARGESIZE)
            return code
        counter = 0
        while True:
            try:
                data = self._recieve_message()
                if data.strip() == self.GOAHEAD:
                    self._send_message(self.s,self.GOAHEAD)
                    code = self._receive_message(size=self.LARGESIZE)
                    return code
                else:
                    return False
            except:
                counter += 1
                if counter >= 10:#arbitrary
                    return False
    def get_scores(self,match_name):#nt
        self._initiate_connection(generate_key=False)
        self._send_message(self.s,self.CHECKSCORES,setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,match_name,setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,self.USER_NAME,setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,self.GOAHEAD,setup=True)
        user_score = self._recieve_message(setup=True)
        self._send_message(self.s,self.GOAHEAD,setup=True)
        opponent_score = self._recieve_message(setup=True)
        return(user_score,opponent_score)
    def upload_score(self,token,score):#nt
        self._initiate_connection(generate_key=False)
        self._send_message(self.s,self.CHECKSCORES,setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,match_name,setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,self.USER_NAME,setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,token,setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        self._send_message(self.s,str(score),setup=True)
        data = self._recieve_message(setup=True)
        if data.strip() != self.GOAHEAD:
            self._error_handling(data)
        return True
if __name__ == "__main__":      
    c = connection()
    #a = c.get_auth_token()
    print(c.ping())
    time.sleep(1)
    name = c.upload("this do be a test 2699","testing234",shared=False)
    time.sleep(1)
    print(c.view(name))
    time.sleep(1)
    c.share(name,"test")
    time.sleep(1)
    print(c.get_ownership(name))
    time.sleep(1)
    c.delete(name)
    #print(a)
    #c.create_account("Fraz900","admin")
    #c.upload("this is a test","testing")

