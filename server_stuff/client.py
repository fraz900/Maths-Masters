import socket
import hashlib

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
        
    def _send_message(self,sock,message):
        print(f"sent : {message}")
        sock.sendall(message.encode())

    def _recieve_message(self,size=1024):
        data = self.s.recv(size)
        data = data.decode()
        print(f"recieved : {data}")
        return data

    def _error_handling(self,error):
        try:
            error = self.WARNINGS[data.decode()]
        except KeyError:
            error = "UNKNOWN ERROR"
        print("error")
        raise Exception(error)
    def _initiate_connection(self):
        self.s.connect((self.SERVER_IP,self.PORT))
        data = self._recieve_message()
        if data != self.GOAHEAD:
            self._error_handling(data)
            return False
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
    #a = c.get_auth_token()
    #print(a)
    c.create_account("test","ay")


#TODO
#get refresh code (expires after a week)
#data uploading keeping scope in mind

