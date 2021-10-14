import socket            
import secrets
import hashlib
import time

class connection():
    def __init__(self):
        self.s = socket.socket()
        self.PORT = 12345
        self.FAILURE = "400"
        self.ERROR = "401"
        self.GOAHEAD = "200"
    def main(self):             
        self.s.bind(("",self.PORT))
        self.s.listen(5)
        while True:
            c,addr = self.s.accept()
            
            print("got connection from",addr)
            
            c.send(self.GOAHEAD.encode())
            
            data = c.recv(1024)
            command = data.decode()
            command = command.strip()
            if command == "ra":
                c.send(self.GOAHEAD.encode())
                data = c.recv(1024)
                data = data.decode()
                self.refresh_token(c,data)
            
            else:
                c.send(self.ERROR.encode())
                c.close()
            print(command)
            

    def refresh_token(self,user,refresh_code):
        file = open("refresh_codes.txt","r")
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
            user.send(auth_code.encode())
            user.close()
            current_time = time.time()
            file = open("active_auth_codes.txt","a")
            addition = f"{person},{auth_code},{current_time}\n"
            file.write(addition)
            file.close()
        else:
            user.send(self.FAILURE.encode())
            user.close()

    def check_auth(self,auth_code):
        file = open("active_auth_codes.txt","r")
        content = file.read()
        file.close()
        content = content.split("\n")
        for line in content:
            line = line.split("\n")
            check = line[1]

            if auth_code == check:
                time_check = line[2]
                current_time = time.time()
                time_check = float(time_check)
                if (current_time - time_check) < 3600:
                    return True
                
            return False

a = connection()
a.main()

