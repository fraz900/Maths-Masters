import socket

class connection():
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SERVER_IP = "127.0.0.1" # server IP adress
        self.PORT = 12345 #arbitrary value
        self.AUTH = "11a3"

    def send_message(self,sock,message):
        sock.sendall(message.encode())

    def get_auth_token(self):
        commands = ["ra",self.AUTH]
        self.s.connect((self.SERVER_IP,self.PORT))
        for command in commands:
            print(command)
            data = self.s.recv(1024)
            print(data.decode())
            if data.decode() != "200":
                print("no")
                return False
            self.s.send(command.encode())
        data = self.s.recv(1024)
        return(data.decode())
            
        
        

c = connection()
a = c.get_auth_token()
print(a)
#c.send_message(c.s,"test")

