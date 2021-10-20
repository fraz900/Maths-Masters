import socket            
import secrets
import hashlib
import time
import threading

class connection():
    def __init__(self):
        #network things
        self.s = socket.socket()
        self.PORT = 12345
        #codes
        self.FAILURE = "400"
        self.ERROR = "401"
        self.GOAHEAD = "200"
        #files
        self.AUTHCODES = "active_auth_codes.txt"
        self.REFRESHCODES = "refresh_codes.txt"
        #commands
        self.REFRESHAUTH = "rac"
        
    def start(self)->None:             
        self.s.bind(("",self.PORT))
        self.s.listen(5)
        while True:
            c,addr = self.s.accept()
            
            print("got connection from",addr)
            
            threading.Thread(target=self.handler,args=[c]).start()

    def handler(self,c)->None:
        self._send_message(c,self.GOAHEAD)
        command = self._recieve_message(c)
        if not command:
            return
        command = command.strip()
        match command:
            case self.REFRESHAUTH:
                threading.Thread(target=self.refresh_token,args=[c]).start()
            case _:
                self._send_message(c,self.FAILURE)
                c.close()
        print(command)

    def _send_message(self,sock,message)->None:
        sock.sendall(message.encode())
    def _recieve_message(self,sock)-> str:
        try:
            data = sock.recv(1024)
            return(data.decode())
        except ConnectionResetError:
            return False
    
    def refresh_token(self,user):
        self._send_message(user,self.GOAHEAD)
        refresh_code = self._recieve_message(user)
        if not refresh_code:
            return
        file = open(self.REFRESHCODES,"r")
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
            self._send_message(user,self.FAILURE)
            user.close()

    def check_auth(self,auth_code):
        file = open(self.AUTHCODES,"r")
        content = file.read()
        file.close()
        content = content.split("\n")
        for line in content:
            line = line.split(",")
            check = line[1]

            if auth_code == check:
                time_check = line[2]
                current_time = time.time()
                time_check = float(time_check)
                if (current_time - time_check) < 3600:
                    return True
                
            return False
    def clear_codes(self,file_name,time_limit):
        file = open(file_name,"r")
        content = file.read()
        file.close()
        content = content.split("\n")
        for line in content:
            formated_line = line.split(",")
            if "," not in line:
                content.remove(line)
            try:
                time_check = formated_line[2]
            except IndexError:
                None
            current_time = time.time()
            time_check = float(time_check)
            if (current_time - time_check) > time_limit:
                content.remove(line)

        final = ""
        for line in content:
            final += line
            final += "\n"
        file = open(self.AUTHCODES,"w")
        file.write(final)
        file.close()

if __name__ == "__main__":
    a = connection()
    a.clear_codes("active_auth_codes.txt",3600)
    a.start()

