import socket
import hashlib
from encryption import DH,AES
class connection():
    def __init__(self):
        #network things
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SERVER_IP = "127.0.0.1"
        self.PORT = 12345
        #commands
        self.REFRESHAUTH_COMMAND = "rac"
        self.CREATEACCOUNT = "ca"
        self.UPLOADDATA = "ud"
        #responses
        self.GOAHEAD = "200"
        self.WARNINGS = {"400":"client error, incorrect command","401":"authentication error, failure to authenticate","500":"Data not allowed"}

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

        self.AUTHCODE = None
        self.LARGESIZE = 20000
        self.UPLOADS = "uploads.txt"
        
    def _send_message(self,sock,message,setup=False):
        message = str(message)
        print(f"sent : {message}")
        if setup:
            sock.sendall(str(message).encode())
        else:
            a = AES(message)
            encrypted_message = a.encrypt(self.key)
            print(self._size(encrypted_message))
            sock.sendall(encrypted_message.encode())
            
    def _recieve_message(self,size=1024,setup=False):
        data = self.s.recv(size)
        data = data.decode()
        if setup:
            print(f"recieved : {data}")
            return data.strip()
        else:
            a = AES(data)
            message = a.decrypt(self.key)
            print(f"recieved : {message}")
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
    def _initiate_connection(self):
        self.s.connect((self.SERVER_IP,self.PORT))
        data = self._recieve_message(setup=True)
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False

        generate_key = True
        if generate_key:
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
    def get_auth_token(self):
        commands = [self.REFRESHAUTH_COMMAND,self.REFRESH_CODE]
        self._initiate_connection()
        first = True
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

            
    def upload(self,data_to_send,name,recurse=False):
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
        return True
        
class communication():
    def __init__(self):
        None

    def upload(self,data):
        None

    def update(self,change,name):
        None

    def delete(self,name):
        None
if __name__ == "__main__":      
    c = connection()
    #a = c.get_auth_token()
    #print(a)
    #c.create_account("Fraz900","admin")
    c.upload("this is a test","testing")

#TODO
#data uploading keeping scope in mind
#limitted storage of auth codes to stop avoidable traffic

