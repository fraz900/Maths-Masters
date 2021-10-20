import socket

class connection():
    def __init__(self):
        #network things
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SERVER_IP = "127.0.0.1"
        self.PORT = 12345
        #commands
        self.REFRESHAUTH_COMMAND = "rac"
        self.REFRESHREFRESH_COMMAND = "rrc"
        #responses
        self.GOAHEAD = "200"
        self.WARNINGS = {"400":"client error, incorrect command","401":"authentication error, failure to authenticate"}

        #other
        self.REFRESH_CODE = "11a3"
        
    def _send_message(self,sock,message):
        print(message)
        sock.sendall(message.encode())

    def get_auth_token(self):
        commands = [self.REFRESHAUTH_COMMAND,self.REFRESH_CODE]
        self.s.connect((self.SERVER_IP,self.PORT))
        for command in commands:
            print(command)
            data = self.s.recv(1024)
            print(data.decode())
            if data.decode() != self.GOAHEAD:
                try:
                    error = self.WARNINGS[data.decode()]
                except KeyError:
                    error = "UNKNOWN ERROR"
                print("error")
                raise Exception(error)
            
                return False
            #self._send_message(self.s,command)
        data = self.s.recv(1024)
        return(data.decode())




if __name__ == "__main__":      
    c = connection()
    a = c.get_auth_token()
    print(a)




