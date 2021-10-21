import secrets
import sys
import random
from math import gcd
class AES():
    def __init__(self,data):
        self.data = data
        self.padding = "00100000"# a space (32)
        self.constant_matrix = [["00000010","00000011","00000001","00000001"],
                                ["00000001","00000010","00000011","00000001"],
                                ["00000001","00000001","00000010","00000011"],
                                ["00000011","00000001","00000001","00000010"]]
    def __repr__(self):
        return self.data
    def generate_key(self):
        key = secrets.token_bytes(20)
        bin_key = bin(int.from_bytes(key, byteorder=sys.byteorder))
        fkey = bin_key.replace("0b","0")
        fkey = fkey[:128]
        return fkey

    def encrypt(self,key):
        blocks = self._blocks(self.data)
        final = []
        for block in blocks:
            ciphertext = self._encrypting(key,block)
            final.append(ciphertext)
        output = ""
        for value in final:
            output += value + " "
        self.data = output
        return output

    def decrypt(self,key):
        data = self.data.split(" ")
        answers = []
        for ciphertext in data:
            plaintext = self._decrypting(key,ciphertext)
            readable = self._binary2text(plaintext)[:4]
            answers.append(readable)
        final = "".join(answers)
        self.data = final
        return final
    
    def _encrypting(self,key,data):
        result = ""
        #byte substitution
        #chunks = self._matrix(self.data)
        chunks = self._matrix(data)
        #shift rows
        for chunk in chunks:
            thing = self._encryptor(chunk,key,0)
            result += thing

        return result
    def _encryptor(self,chunk,key,count):
        matrix = []
        for i in range(0,len(chunk),4):
            holder = chunk[i:i+4]
            matrix.append(holder)
        new_matrix = []
        counter = 0
        for line in matrix:
            new_line = self._rotate(line,counter)
            new_matrix.append(new_line)
            counter += 1


        #mix columns
        counter1 = 0
        final_matrix = []
        for row in new_matrix:
            counter2 = 0
            final_line = []
            for byte in row:
                new_byte = self._xor(byte,self.constant_matrix[counter1][counter2])
                new_byte = byte
                final_line.append(new_byte)
                counter2 += 1
            final_matrix.append(final_line)
            counter1 += 1

        #add key
        concat = ""
        for row in final_matrix:
            for element in row:
                concat += element

        result = self._xor(concat,key)
        if count > 3:
            return result
        count += 1
        matrix = []
        for i in range(0,len(result),8):
            chunk = result[i:i+8]
            matrix.append(chunk)
        actual = self._encryptor(matrix,key,count)
        return actual

    def _decrypting(self,key,ciphertext):
        grids = []
        for i in range(0,len(ciphertext),128):
            holder = ciphertext[i:i+128]
            grids.append(holder)
        result = ""
        for grid in grids:
            result += self._decryptor(key,grid,0)
        return result

    def _decryptor(self,key,grid,counter):
        unkeyed = self._xor(grid,key)
        thing = []
        for i in range(0,len(unkeyed),8):
            holder = unkeyed[i:i+8]
            thing.append(holder)
        chunks = []
        for i in range(0,len(thing),4):
            holder = thing[i:i+4]
            chunks.append(holder)
        final = ""
        for chunk in chunks:
            matrix = []
            for i in range(0,len(chunk),4):
                holder = chunk[i:i+4]
                matrix.append(holder)
            counter1 = 0
            final_matrix = []
            for row in matrix:
                counter2 = 0
                final_line = []
                for byte in row:
                    new_byte = self._xor(byte,self.constant_matrix[counter1][counter2])
                    new_byte = byte
                    final_line.append(new_byte)
                    counter2 += 1
                final_matrix.append(final_line)
                counter1 += 1

            new_matrix = []
            counter3 = 0
            for line in matrix:
                scale = len(line) - counter3
                new_line = self._rotate(line,scale)
                new_matrix.append(new_line)
                counter3 += 1

            concat = ""
            for row in new_matrix:
                for element in row:
                    concat += element
            final += concat
        if counter > 3:
            return final
        counter += 1
        result = self._decryptor(key,final,counter)
        return result


        

    def _xor(self,binary1,binary2):
        final = ""
        if len(binary1) != len(binary2):
            print("bin1",binary1)
            print("bin2",binary2)
            raise ValueError("values must be of same length")
            #both elements must be the same length
        for x in range(0,len(binary1)):
            num1 = binary1[x]
            num2 = binary2[x]
            if num1 == "1":
                if num2 == "1":
                    final += "0"
                else:
                    final += "1"
            elif num2 == "1":
                final += "1"
            else:
                final += "0"
        return(final)
        
        
    def _rotate(self,a_list,shift):
        return a_list[shift:] + a_list[:shift]

    def _matrix(self,content,binary=False): 
        if not binary:
            binary_content = self._text2binary(content)
        else:
            binary_content = content
        while len(binary_content) % 16 != 0:
            binary_content.append(self.padding)
        matrix = []
        for i in range(0,len(binary_content),16):
            chunk = binary_content[i:i+16]
            matrix.append(chunk)
        return matrix

    def _text2binary(self,string):
        string = string.encode()
        value = []
        for byte in string:
            value.append(format(byte,"08b"))
        return(value)
    def _binary2text(self,plaintext):
        letter = ""
        final = ""
        word = []
        for digit in plaintext:
            letter += digit
            if len(letter) == 8:
                word.append(letter)
                letter = ""
        for item in word:
            item = int(item,2)
            final += chr(item)
        return final

    def _blocks(self,data):
        while len(data) % 4 != 0:
            data += " "
        information = []
        for i in range(0,len(data),4):
            holder = data[i:i+4]
            information.append(holder)
        return information


class DH():
    def __init__(self):
        None
    def generate_prime(self,length):
        first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                             31, 37, 41, 43, 47, 53, 59, 61, 67,
                             71, 73, 79, 83, 89, 97, 101, 103,
                             107, 109, 113, 127, 131, 137, 139,
                             149, 151, 157, 163, 167, 173, 179,
                             181, 191, 193, 197, 199, 211, 223,
                             227, 229, 233, 239, 241, 251, 257,
                             263, 269, 271, 277, 281, 283, 293,
                             307, 311, 313, 317, 331, 337, 347, 349]
         
        def nBitRandom(n):
            return random.randrange(2**(n-1)+1, 2**n - 1)
         
        def getLowLevelPrime(n):
            while True:
                num = nBitRandom(n)
                for prime_number in first_primes_list:
                    if num % prime_number == 0 and prime_number**2 <= num:
                        break
                else:
                    return num
         
        def isMillerRabinPassed(num):
            maxDivisionsByTwo = 0
            ec = num-1
            while ec % 2 == 0:
                ec >>= 1
                maxDivisionsByTwo += 1
            if not 2**maxDivisionsByTwo * ec == num-1:
                raise Exception("not prime")
            def trialComposite(round_tester):
                if pow(round_tester, ec, num) == 1:
                    return False
                for i in range(maxDivisionsByTwo):
                    if pow(round_tester, 2**i * ec, num) == num-1:
                        return False
                return True
         
            numOfTests = 20
            for i in range(numOfTests):
                round_tester = random.randrange(2, num)
                if trialComposite(round_tester):
                    return False
            return True
        while True:
            num = getLowLevelPrime(length)
            if isMillerRabinPassed(num):
                return num

    def equation(self,base,a,modulus):
        A = (base**a) % modulus
        return A

    
if __name__ == "__main__":
    check = "DH" #or "AES"
    if check == "AES":
        test_string = "this is a test string"
        a = AES(test_string)
        key = a.generate_key()
        a.encrypt(key)
        print(a)
        a.decrypt(key)
        print(a)
    elif check == "DH":
        a = DH()
        modulus = a.generate_prime(2048)
        print(modulus)
        print()
        test = a.equation(12345,12345,modulus)
        print(test)
        #print(a.prim_root(modulus))
       
