def encryptAtbashCipher(enc):
    result = []
    for char in enc:
        if char.isalpha():
            inEnc = ord('z') + ord('a') - ord(char)
            result.append(chr(inEnc))
        else:
            result.append(char)
    print("".join(result))
    return "".join(result)


def decryptAtbashCipher(dec):
    encryptAtbashCipher(dec)


def encryptCaesarCipher(text, key):
    result = []
    symbols = {
        '.': ',',',': '.',
        '!': '?','?': '!',
        '0': '1','1': '0',
        '2': '3','3': '2',
        '4': '5','5': '4',
        '6': '7','7': '6',
        '8': '9','9': '8'
    }
    key = key % 26
    for char in text:
        inEnc = ord(char) + key
        if inEnc >= 97:
            if inEnc > 122:
                inEnc = inEnc % 122 + 96
            result.append(chr(inEnc))
        elif inEnc >= 65:
            if inEnc > 90:
                inEnc = inEnc % 90 + 64
            result.append(chr(inEnc))
        elif char in symbols:
            result.append(symbols[char])
        else:
            result.append(char)

    print(''.join(result))
    return ''.join(result)


def decryptCaesarCipher(text, key):
    result = []
    symbols = {
        '.': ',', ',': '.',
        '!': '?', '?': '!',
        '0': '1', '1': '0',
        '2': '3', '3': '2',
        '4': '5', '5': '4',
        '6': '7', '7': '6',
        '8': '9', '9': '8'
    }
    key = key % 26
    for char in text:
        if char.isalpha():
            if char.islower():
                inEnc = ord(char) - key
                if inEnc < 97:
                    inEnc += 26
                result.append(chr(inEnc))
            else:
                inEnc = ord(char) - key
                if inEnc < 65:
                    inEnc += 26
                result.append(chr(inEnc))
        elif char in symbols:
            result.append(symbols[char])
        else:
            result.append(char)
    print(''.join(result))
    return ''.join(result)


def encryptVigenereCipher(text, k_list):
    k_num = len(k_list)
    result = []
    symbols = {
        '.': ',', ',': '.',
        '!': '?', '?': '!',
        '0': '1', '1': '0',
        '2': '3', '3': '2',
        '4': '5', '5': '4',
        '6': '7', '7': '6',
        '8': '9', '9': '8'
    }
    for i, char in enumerate(text):
        if char.isalpha():
            shift = k_list[i % k_num]
            if char.islower():
                inEnc = ord(char) + shift
                if inEnc > 122:
                    inEnc += 26
            else:
                inEnc = ord(char) + shift
                if inEnc > 90:
                    inEnc += 26
            result.append(chr(inEnc))
        elif char in symbols:
            result.append(symbols[char])
        else:
            result.append(char)
    print(''.join(result))
    return ''.join(result)


def decryptVigenereCipher(text, k_list):
    k_num = len(k_list)
    result = []
    symbols = {
        '.': ',', ',': '.',
        '!': '?', '?': '!',
        '0': '1', '1': '0',
        '2': '3', '3': '2',
        '4': '5', '5': '4',
        '6': '7', '7': '6',
        '8': '9', '9': '8'
    }

    for i, char in enumerate(text):
        if char.isalpha():
            shift = k_list[i % k_num]
            if char.islower():
                inEnc = ord(char) - shift
                if inEnc < 97:
                    inEnc += 26
            else:
                inEnc = ord(char) - shift
                if inEnc < 65:
                    inEnc += 26
            result.append(chr(inEnc))
        elif char in symbols:
            result.append(symbols[char])
        else:
            result.append(char)
    print(''.join(result))
    return ''.join(result)


def encryptSimpleEnigmaCipher(text, keys):
    result = []
    k1, k2, k3 = keys
    for char in text:
        if char.isalpha():
            if char.islower():
                char_number = ord(char.lower()) - 97
                changed_1 = (ord(k1[char_number]) - 97) % 26
                changed_2 = (ord(k2[changed_1]) - 97) % 26
                changed_3 = (ord(k3[changed_2]) - 97) % 26
                result.append(chr(changed_3 + 97))
            else:
                char_number = ord(char.lower()) - 97
                changed_1 = (ord(k1[char_number]) - 97) % 26
                changed_2 = (ord(k2[changed_1]) - 97) % 26
                changed_3 = (ord(k3[changed_2]) - 97) % 26
                result.append(chr(changed_3 + 65))
        else:
            result.append(char)
    print(''.join(result))
    return ''.join(result)

def decryptSimpleEnigmaCipher(text, keys):
    result = []
    k1, k2, k3 = keys
    for char in text:
        if char.isalpha():
            if char.islower():
                inEnc = ord(char.lower()) - 97
                for i in range(26):
                    if (ord(k3[i]) - 97) % 26 == inEnc:
                        changed_2 = i
                for i in range(26):
                    if (ord(k2[i]) - 97) % 26 == changed_2:
                        changed_1 = i
                for i in range(26):
                    if (ord(k1[i]) - 97) % 26 == changed_1:
                        inEnc = i
                result.append(chr(inEnc + 97))
            else:
                inEnc = ord(char.lower()) - 97
                for i in range(26):
                    if (ord(k3[i]) - 97) % 26 == inEnc:
                        changed_2 = i
                for i in range(26):
                    if (ord(k2[i]) - 97) % 26 == changed_2:
                        changed_1 = i
                for i in range(26):
                    if (ord(k1[i]) - 97) % 26 == changed_1:
                        inEnc = i
                result.append(chr(inEnc + 65))
        else:
            result.append(char)
    print(''.join(result))
    return ''.join(result)
