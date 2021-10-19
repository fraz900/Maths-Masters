#remove for production
import secrets
import sys
class information():
    def __init__(self,data):
        self.data = data
        self.padding = "00100000"# a space (32)
        self.constant_matrix = [["00000010","00000011","00000001","00000001"],
                                ["00000001","00000010","00000011","00000001"],
                                ["00000001","00000001","00000010","00000011"],
                                ["00000011","00000001","00000001","00000010"]]

    def generate_key(self):
        key = secrets.token_bytes(20)
        bin_key = bin(int.from_bytes(key, byteorder=sys.byteorder))
        fkey = bin_key.replace("0b","0")
        fkey = fkey[:128]
        return fkey
    def encrypt(self,key):
        result = ""
        #byte substitution
        chunks = self._matrix(self.data)
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

    def decrypt(self,key,ciphertext):
        grids = []
        for i in range(0,len(ciphertext),128):
            holder = ciphertext[i:i+128]
            grids.append(holder)
        result = ""
        for grid in grids:
            result += self._decryptor(key,grid,0)
        return result

    def _decryptor(self,key,grid,counter):
        print("ello")
        unkeyed = self._xor(grid,key)
        #chunks = self._matrix(unkeyed,binary=True)
        print("unkeyed",unkeyed)
        thing = []
        for i in range(0,len(unkeyed),8):
            holder = unkeyed[i:i+8]
            thing.append(holder)
        print(thing,"thing")
        chunks = []
        for i in range(0,len(thing),4):
            holder = thing[i:i+4]
            chunks.append(holder)
        print("chunks",chunks)
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
            print(f"concat {concat}")
            print()
            final += concat
        if counter > 3:
            return final
        counter += 1
        result = self._decryptor(key,final,counter)
        return result


        

    def _xor(self,binary1,binary2): #tick
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
        
        
    def _rotate(self,a_list,shift): #tick?
        return a_list[shift:] + a_list[:shift]

    def _matrix(self,content,binary=False): #cannot take binary input (or can it? if decoded twice does it work?)
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

    def _text2binary(self,string): #tick
        string = string.encode()
        value = []
        for byte in string:
            value.append(format(byte,"08b"))
        return(value)
    def _binary2text(self,plaintext): #tick
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

if __name__ == "__main__":

    a = information("this is a pretty cool test")
    key = a.generate_key()
    ciphertext = a.encrypt(key)
    print(f"ciphertext: {ciphertext}")
    print()
    plaintext = a.decrypt(key,ciphertext)
    print(f"decoded = {plaintext}")
    print(a._binary2text(plaintext))

    

