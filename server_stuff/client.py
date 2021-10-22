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
        self.REFRESHREFRESH_COMMAND = "rrc"
        self.CREATEACCOUNT = "ca"
        #responses
        self.GOAHEAD = "200"
        self.WARNINGS = {"400":"client error, incorrect command","401":"authentication error, failure to authenticate"}

        #other
        self.REFRESH_CODE = "11a3"
        
    def _send_message(self,sock,message,setup=False):
        print(f"sent : {message}")
        if setup:
            sock.sendall(str(message).encode())
        else:
            a = AES(message)
            encrypted_message = a.encrypt(self.key)
            sock.sendall(encrypted_message.encode())
            
    def _recieve_message(self,size=1024,setup=False):
        data = self.s.recv(size)
        data = data.decode()
        if setup:
            print(f"recieved : {data}")
            return data
        else:
            a = AES(data)
            message = a.decrypt(self.key)
            print(f"recieved : {message}")
            return message

    def _error_handling(self,error):
        error = str(error)
        error = error.strip()
        try:
            error = self.WARNINGS[error]
        except KeyError:
            error = "UNKNOWN ERROR"
        print("error")
        raise Exception(error)
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
            self._send_message(self.s,base,setup=True)
            self._send_message(self.s,ag,setup=True)
            bg = int(self._recieve_message(setup=True))
            final = diffie.equation(bg,dhKey,modulus)
            a = AES("")
            self.key = a.produce_key(final)
            #print("final",self.key)
    def get_auth_token(self):
        commands = [self.REFRESHAUTH_COMMAND,self.REFRESH_CODE]
        self._initiate_connection()
        first = True
        for command in commands:
            if not first:
                data = self._recieve_message()
                if data != self.GOAHEAD:
                    self._error_handling(data)
                    return False
            else:
                first = False
            self._send_message(self.s,command)
        data = self._recieve_message()
        return(data)







    def create_account(self,username,password):#NEEDS FINISHING
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
            password_test = self._recieve_message()
            if user_test == username and password_test == password:
                correct = True

        self._send_message(self.s,self.GOAHEAD)
        return True
        
        


class communication():
    def __init__(self):
        None


if __name__ == "__main__":      
    c = connection()
    a = c.get_auth_token()
    print(a)
    #c.create_account("test","ay")


#TODO
#data uploading keeping scope in mind

